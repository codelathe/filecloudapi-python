# Copyright (c) 2024 FileCloud. All Rights Reserved.
from dataclasses import dataclass
from enum import Enum
from typing import Optional
from xml.etree.ElementTree import Element


class EntryType(Enum):
    dir = "dir"
    file = "file"


class SharedType(Enum):
    notshared = ""
    private = "private"
    public = "public"


class AclEntryType(Enum):
    user = "user"


ETag = str


@dataclass
class FileListEntry:
    path: str
    dirpath: str
    name: str
    ext: str
    fullsize: int
    modified: str
    type: EntryType
    fullfilename: str
    size: str
    modifiedepoch: str
    isroot: bool
    locked: bool
    isshared: SharedType
    modifiedepochutc: str
    canupload: bool
    candownload: bool
    canrename: bool
    cansetacls: bool
    isshareable: bool
    issyncable: bool
    isdatasyncable: bool
    etag: ETag


@dataclass
class FileVersion:
    versionnumber: str
    size: str
    how: str
    createdon: str
    createdby: str
    filename: str
    sizeinbytes: str
    fileid: str


@dataclass
class FileList:
    parentpath: str
    total: int
    realpath: str
    isroot: bool
    entries: list[FileListEntry]


class SortBy(Enum):
    NAME = "name"
    DATE = "date"
    SIZE = "size"


class SortDir(Enum):
    ascending = 1
    descending = -1


@dataclass
class FCShare:
    shareid: str
    sharename: str
    sharelocation: str
    allowpublicaccess: bool
    allowpublicupload: bool
    allowpublicviewonly: bool
    allowpublicuploadonly: bool
    maxdownloads: Optional[int] = 0
    validityperiod: Optional[str] = ""


@dataclass
class FCShareUser:
    name: str
    read: bool
    write: bool
    sync: bool
    share: bool
    download: bool
    disallowdelete: bool
    allowmanage: bool

    def __getitem__(self, key):
        if key in self.__annotations__:
            return getattr(self, key)
        else:
            raise KeyError(f"'{key}' property not found")


@dataclass
class FCShareGroup:
    groupid: str
    groupname: str
    read: bool
    write: bool
    sync: bool
    share: bool
    download: bool
    disallowdelete: bool

    def __getitem__(self, key):
        if key in self.__annotations__:
            return getattr(self, key)
        else:
            raise KeyError(f"'{key}' property not found")


@dataclass
class ShareActivity:
    shareid: str
    path: str
    name: str
    actioncode: int
    who: str
    when: str
    how: str
    ip: str


@dataclass
class FileLockInfo:
    locked: bool
    readlock: bool
    lockedby: str


@dataclass
class TeamFolderInfo:
    teamfolderenabled: bool
    teamfolderaccount: str
    aclenabled: bool
    teamfolderpath: Optional[str] = None


@dataclass
class NetworkFolderInfo:
    networkfoldername: str


@dataclass
class RMCClient:
    rid: str
    remote_client_id: str
    remote_client_disp_name: str
    remote_client_last_login: str
    remote_client_status: int
    remote_client_status_message: str


@dataclass
class PolicyUser:
    username: str
    status: int
    adminstatus: int
    authtype: int


@dataclass
class SyncFolder:
    path: str
    update_version: int


@dataclass
class SyncDeltaItem:
    type: EntryType
    size: int
    modified: str
    name: str
    fullpath: str
    flags: str
    isdeleted: bool
    updateversion: int
    candownload: bool
    canupload: bool
    canrename: bool
    etag: str


@dataclass
class AclPermissions:
    has_read_permission: bool
    has_write_permssion: bool
    has_share_permission: bool
    has_delete_permission: bool

    def __init__(self, fromstr: str):
        self.has_read_permission = False
        self.has_write_permssion = False
        self.has_share_permission = False
        self.has_delete_permission = False
        if "R" in fromstr:
            self.has_read_permission = True
        if "W" in fromstr:
            self.has_write_permssion = True
        if "S" in fromstr:
            self.has_share_permission = True
        if "D" in fromstr:
            self.has_delete_permission = True

    def __str__(self) -> str:
        ret = ""
        if self.has_read_permission:
            ret += "R"
        if self.has_write_permssion:
            ret += "W"
        if self.has_share_permission:
            ret += "S"
        if self.has_delete_permission:
            ret += "D"
        return ret


class UserStatus(Enum):
    GUEST = 0
    FULL = 1
    DISABLED = 2
    EXTERNAL = 3
    UNKNOWN = -1


@dataclass
class PolicyEntry:
    """Represents a policy entry"""

    policyid: str
    policyname: str


class PolicyList:
    """Convienience class represents policy list"""

    entries: list[PolicyEntry] = []

    def first(self) -> PolicyEntry | None:
        if len(self.entries) >= 1:
            return self.entries[0]
        return None

    def __iter__(self):
        return iter(self.entries)

    def __init__(self, a_response: Element):
        """"""
        self._set_entries(response=a_response)

    def _set_entries(self, response: Element):
        a_list = list(response)

        for elem in a_list:
            if elem.tag != "policy":
                continue

            an_entry = PolicyEntry(
                policyid=list(elem)[0].text,  # type:ignore
                policyname=list(elem)[1].text,  # type:ignore
            )
            self.entries.append(an_entry)


class ServerSettings:
    """Convienience class represents server settings"""

    entries: dict = {}

    def __iter__(self):
        return iter(self.entries)

    def __init__(self, a_response: Element):
        """"""
        self._set_entries(response=a_response)

    def _set_entries(self, response: Element):
        a_list = list(response)

        for elem in a_list:
            if elem.tag != "setting":
                continue

            self.entries[list(elem)[0].text] = list(elem)[1].text


@dataclass
class StorageRootDetails:
    type: str
    name: str


@dataclass
class ProfileSettings:
    nickname: str
    peerid: str
    displayname: str
    email: str
    isremote: int
