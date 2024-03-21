from pydantic import BaseModel, Field, field_validator
from datetime import datetime
from util.x509.enums import SignatureAlgorithmOid


class Certificate(BaseModel):
    version: int = Field(ge=0, le=2)
    serial_number: str
    not_valid_before: datetime
    not_valid_after: datetime
    signature_algorithm: SignatureAlgorithmOid

    @field_validator('serial_number')
    @classmethod
    def str_make_upper(cls, value: str) -> str:
        if value[:2].lower() == '0x':
            return value.upper()[2:]
        else:
            return value.upper()


# if __name__ == '__main__':
#     c = Certificate(version=2, serial_number=125425, not_valid_before=datetime.now(), not_valid_after=datetime.now())
#     print(c)
#
#     print(c.model_dump())
#     # for key, value in c:
#     #     print(key.replace('_', ' ').title(), value)
