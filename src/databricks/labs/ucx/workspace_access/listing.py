import datetime as dt
import logging
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from itertools import groupby

from databricks.sdk import WorkspaceClient
from databricks.sdk.core import DatabricksError
from databricks.sdk.service.workspace import ObjectInfo, ObjectType

logger = logging.getLogger(__name__)


class WorkspaceListing:
    def __init__(
        self,
        ws: WorkspaceClient,
        num_threads: int,
        *,
        with_directories: bool = True,
        object_types: list | None = None,
    ):
        if object_types is None:
            self.object_types = [
                ObjectType.DIRECTORY,
                ObjectType.NOTEBOOK,
                ObjectType.REPO,
                ObjectType.FILE,
                ObjectType.LIBRARY,
            ]
        self.start_time = None
        self._ws = ws
        self.results: list[ObjectInfo] = []
        self._num_threads = num_threads
        self._with_directories = with_directories
        self._counter = 0

    def _progress_report(self, _):
        self._counter += 1
        measuring_time = dt.datetime.now()
        delta_from_start = measuring_time - self.start_time
        rps = self._counter / delta_from_start.total_seconds()
        directory_count = len([r for r in self.results if r.object_type == ObjectType.DIRECTORY])

        results_iterator = groupby(self.results, key=lambda x: x.object_type)
        if self._counter % 10 == 0:
            logger.info(f"Made {self._counter} workspace listing calls, collected {len(self.results)} objects, ")
            logger.info(directory_count)
            for obj_type, objects in results_iterator:
                logger.info(f"collected {len(list(objects))} {obj_type} objects")
            logger.info(f" rps: {rps:.3f}/sec")

    def _list_and_analyze(self, obj: ObjectInfo) -> (list[ObjectInfo], list[ObjectInfo]):
        directories = []
        others = []
        try:
            grouped_iterator = groupby(
                self._ws.workspace.list(path=obj.path, recursive=False), key=lambda x: x.object_type
            )
            for object_type, objects in grouped_iterator:
                if object_type == ObjectType.DIRECTORY:
                    objs = list(objects)
                    directories.extend(objs)
                    if ObjectType.DIRECTORY in self.object_types:
                        others.extend(objs)
                elif object_type in self.object_types:
                    others.extend(list(objects))
                else:
                    logger.error(
                        f"{object_type} not a valid type, please choose from {[obj.name for obj in ObjectType]}."
                    )
            logger.debug(f"Listed {obj.path}, found {len(directories)} sub-directories and {len(others)} other objects")
        except DatabricksError as err:
            # See https://github.com/databrickslabs/ucx/issues/230
            if err.error_code != "RESOURCE_DOES_NOT_EXIST":
                raise err
            logger.warning(f"{obj.path} is not listable. Ignoring")
        return directories, others

    def walk(self, start_path="/"):
        self.start_time = dt.datetime.now()
        logger.info(f"Recursive WorkspaceFS listing started at {self.start_time}")
        root_object = self._ws.workspace.get_status(start_path)
        self.results.append(root_object)

        with ThreadPoolExecutor(self._num_threads) as executor:
            initial_future = executor.submit(self._list_and_analyze, root_object)
            initial_future.add_done_callback(self._progress_report)
            futures_to_objects = {initial_future: root_object}
            while futures_to_objects:
                futures_done, futures_not_done = wait(futures_to_objects, return_when=FIRST_COMPLETED)

                for future in futures_done:
                    futures_to_objects.pop(future)
                    directories, others = future.result()
                    self.results.extend(others)

                    if directories:
                        new_futures = {}
                        for directory in directories:
                            new_future = executor.submit(self._list_and_analyze, directory)
                            new_future.add_done_callback(self._progress_report)
                            new_futures[new_future] = directory
                        futures_to_objects.update(new_futures)

            logger.info(
                f"Recursive WorkspaceFS listing finished at {dt.datetime.now()}. "
                f"Total time taken for workspace listing: {dt.datetime.now() - self.start_time}"
            )
            self._progress_report(None)
        return self.results
