"""Class-body and annotation oracle, deliberately without inherited future flags."""


class SourceRecord:
    label: str = 'record'

    def size(self) -> int:
        return len(self.label)
