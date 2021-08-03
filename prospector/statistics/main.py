from __future__ import annotations

from typing import Optional, Tuple, Union

from util.inspection import caller_name


class ForbiddenDuplication(ValueError):
    ...


LEVEL_DELIMITER = "."


class StatisticCollection(dict):
    def record(self, name: Union[str, Tuple[str, ...]], value, overwrite=False):
        if isinstance(name, str):
            if not overwrite and name in self:
                raise ForbiddenDuplication(f"{name} already added")

            if LEVEL_DELIMITER in name:
                raise ValueError(
                    f"do not use level delimiter {LEVEL_DELIMITER} in names,"
                    " hierarchical entries should be specified by tuples"
                )
            else:
                self[name] = value
        elif isinstance(name, tuple):
            if len(name) == 1:
                self.record(name[0], value)
            elif len(name) > 1:
                current_name = name[0]
                if current_name not in self:
                    self[current_name] = StatisticCollection()
                current_collection = self[current_name]
                if not isinstance(current_collection, StatisticCollection):
                    raise ForbiddenDuplication(
                        f"{name} already added as a single value"
                    )
                else:
                    current_collection.record(name[1:], value)
        else:
            raise ValueError("only string or tuple keys are enabled")

    def sub_collection(
        self,
        parent_name: Optional[Union[str, Tuple[str, ...]]] = None,
        sub_collection: Optional[StatisticCollection] = None,
    ):
        if parent_name is None:
            parent_name = caller_name()

        if parent_name not in self:
            if sub_collection is None:
                sub_collection = StatisticCollection()
            self.record(parent_name, sub_collection)

    def __getitem__(self, key: Union[str, Tuple[str, ...]]):
        if isinstance(key, str):
            return super().__getitem__(key)
        elif isinstance(key, tuple):
            if len(key) == 1:
                return self[key[0]]
            elif len(key) > 1:
                current_collection = self[key[0]]
                if isinstance(current_collection, StatisticCollection):
                    return current_collection[key[1:]]
                else:
                    raise KeyError(f"{key[0]} is a single value")
            else:
                raise KeyError("empty key are not allowed")
        else:
            raise KeyError("only string ot tuple keys allowed")

    def __contains__(self, key):
        if isinstance(key, str):
            return super().__contains__(key)
        elif isinstance(key, tuple):
            if len(key) == 1:
                return key[0] in self
            elif len(key) > 1:
                if key[0] not in self:
                    return False
                current_collection = self[key[0]]
                if isinstance(current_collection, StatisticCollection):
                    return key[1:] in current_collection
                else:
                    raise KeyError(f"{key[0]} is a single value")
            else:
                raise KeyError("empty key are not allowed")
        else:
            raise KeyError("only string ot tuple keys allowed")

    def collect(self, name: Union[str, Tuple[str, ...]], value):
        if name not in self:
            self.record(name, [])

        if isinstance(self[name], list):
            self[name].append(value)
        else:
            raise KeyError(f"can not collect into {name}, because it is not a list")

    def collect_unique(
        self, name: Union[str, Tuple[str, ...]], value, ensure_uniqueness: bool = False
    ):
        if name not in self:
            self.record(name, set())

        if isinstance(self[name], set):
            if not ensure_uniqueness or not (value in self[name]):
                self[name].add(value)
        else:
            raise KeyError(f"can not collect into {name}, because it is not a set")

    def increment(self, name: Union[str, Tuple[str, ...]], by: Union[int, float] = 1):
        selected = self[name]
        if isinstance(selected, list) and (
            isinstance(selected[-1], int) or isinstance(selected[-1], float)
        ):
            selected[-1] += by
        elif isinstance(selected, int) or isinstance(selected, float):
            self.record(name, selected + by, overwrite=True)
        else:
            ValueError(f"can not increment {name}")
