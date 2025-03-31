# Copyright (c) 2024 FileCloud. All Rights Reserved.
import datetime
import logging
import pathlib
import re
import threading
import time
import xml.etree.ElementTree as ET
from io import SEEK_CUR, SEEK_END, SEEK_SET, BufferedReader, BytesIO
from pathlib import Path
from typing import Dict, Optional, Union
from urllib.parse import urlencode

import requests
from requests.adapters import HTTPAdapter
from urllib3 import Retry
from urllib3.filepost import RequestField, encode_multipart_formdata

from .datastructures import (
    AclEntryType,
    AclPermissions,
    EntryType,
    FCShare,
    FCShareGroup,
    FCShareUser,
    FileList,
    FileListEntry,
    FileLockInfo,
    FileVersion,
    NetworkFolderInfo,
    PolicyEntry,
    PolicyList,
    PolicyUser,
    RMCClient,
    ShareActivity,
    SharedType,
    SortBy,
    SortDir,
    SyncDeltaItem,
    SyncFolder,
    TeamFolderInfo,
    UserStatus,
    ServerSettings,
)
from .exceptions import ServerError


def str_to_bool(value):
    return value.lower() in ("true", "1", "yes")


log = logging.getLogger(__name__)


class Progress:
    """
    Way to track progress of uploads/downloads.

    Either use this object in another thread or
    override update() to get progress updates.
    """

    def __init__(self) -> None:
        self._completed_bytes = 0
        self._total_bytes = 0
        self._lock = threading.Lock()

    """
    Progress callback of uploads/downloads
    """

    def update(
        self, completed_bytes: int, total_bytes: int, chunk_complete: bool
    ) -> None:
        with self._lock:
            self._completed_bytes = completed_bytes
            self._total_bytes = total_bytes

    def completed_bytes(self) -> int:
        with self._lock:
            return self._completed_bytes

    def total_bytes(self) -> int:
        with self._lock:
            return self._total_bytes


class FCServer:
    """
    FileCloud Server API
    """

    def __init__(
        self,
        url: str,
        email: Optional[str],
        username: str,
        password: str,
        adminlogin: bool = False,
        signinusingusername: bool = True,
        twofakeyfun=None,
        withretries: bool = True,
        login: bool = True,
    ) -> None:
        self.email = email
        self.username = username
        self.password = password
        self.signinusingusername = signinusingusername
        self.twofakeyfun = twofakeyfun
        self.url = url
        self.adminlogin = adminlogin
        self.session = requests.session()
        self.retries: Optional[Retry] = (
            Retry(total=10, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504])
            if withretries
            else None
        )

        self.session.mount("http://", HTTPAdapter(max_retries=self.retries))
        self.session.mount("https://", HTTPAdapter(max_retries=self.retries))

        # Trim trailing slashes, FileCloud generates an error if the URL starts with //
        if self.url[-1] == "/":
            self.url = self.url[:-1]

        if login:
            if adminlogin:
                self.login_as_admin()
            else:
                self.login()

    def _api_call(self, method: str, params: Dict) -> ET.Element:
        """
        Perform a FC API call (post)
        """
        resp = self.session.post(self.url + method, data=params)
        resp.raise_for_status()
        self.last_headers = resp.headers
        return ET.fromstring(resp.content)

    def _api_call_raw(self, method: str, params: Dict) -> str:
        """
        Perform a FC API call (post) and return raw string for i.e. getuploadform
        """
        resp = self.session.post(self.url + method, data=params)
        resp.raise_for_status()
        self.last_headers = resp.headers
        return str(resp.content)

    def _admin_api_call_setlicense(
        self, method: str, params: Dict, files: Optional[Dict] = None
    ) -> bool:
        """
        Perform a FC API call (post) to save the license. The response is either OK or Invalid xml.
        """
        resp = self.session.post(self.url + method, data=params, files=files)
        resp.raise_for_status()
        self.last_headers = resp.headers

        return str(resp.text) == "OK"

    def _extract_server_error_code(self, msg: str) -> str:
        code = re.search(r"CLFC-\d+(?:-\d+)?", msg)
        if code:
            return code.group()
        else:
            return ""

    def _raise_exception_from_server_message(self, msg: str) -> None:
        """
        Raise ServerError from server message
        """
        raise ServerError(self._extract_server_error_code(msg), msg)

    def _raise_exception_from_command(self, resp: ET.Element):
        """
        Raise Server Error from command response if result is not 1
        """
        result = resp.findtext("./command/result", "0")

        if int(result) != 1:
            self._raise_exception_from_server_message(
                resp.findtext("./command/message", "")
            )

    def login(self) -> None:
        """
        Try to login to FC server with the credentials
        provided at init
        """
        resp = self._api_call(
            "/core/loginguest",
            {
                "userid": self.username if self.signinusingusername else self.email,
                "password": self.password,
            },
        )

        res = int(resp.findtext("./command/result", "0"))

        if res == 3:
            # 2FA
            token = resp.findtext("./command/message", "")
            if self.twofakeyfun is None:
                raise ValueError("2FA required but no twofakeyfun provided")

            code: str = self.twofakeyfun()
            resp = self._api_call(
                "/core/2falogin",
                {
                    "userid": self.username,
                    "code": code,
                    "token": token,
                    "password": self.password,
                },
            )

        self._raise_exception_from_command(resp)

    def login_as_admin(self) -> None:
        """
        Try to login to FC server admin portal with the credentials
        provided at init
        """
        resp = self._api_call(
            "/admin/adminlogin",
            {
                "adminuser": self.username if self.signinusingusername else self.email,
                "adminpassword": self.password,
            },
        )

        res = int(resp.findtext("./command/result", "0"))

        if res == 3:
            # 2FA
            token = resp.findtext("./command/message", "")
            if self.twofakeyfun is None:
                raise ValueError("2FA required but no twofakeyfun provided")
            code = self.twofakeyfun()
            resp = self._api_call(
                "/core/2falogin",
                {
                    "userid": self.username,
                    "code": code,
                    "token": token,
                    "password": self.password,
                },
            )

        self._raise_exception_from_command(resp)

    def _parseEntry(self, entry: ET.Element) -> FileListEntry:
        """
        Parse a file entry (e.g. returned by getfilelist)
        """
        fullsize_str = entry.findtext("./fullsize")

        if fullsize_str is None:
            raise ValueError("fullsize in file entry is None in server response")

        fullsize = 0
        if len(fullsize_str) > 0:
            fullsize = int(fullsize_str)

        def bool_opt(txt: Optional[str]) -> bool:
            if txt is not None and len(txt) > 0:
                return int(txt) > 0
            else:
                return False

        def shared_opt(txt: Optional[str]) -> SharedType:
            if txt is not None:
                if txt == "":
                    return SharedType.notshared
                elif txt == "public":
                    return SharedType.public
                elif txt == "private":
                    return SharedType.private
                else:
                    assert txt == ""
                    return SharedType.notshared
            else:
                return SharedType.notshared

        return FileListEntry(
            entry.findtext("./path", ""),
            entry.findtext("./dirpath", ""),
            entry.findtext("./name", ""),
            entry.findtext("./ext", ""),
            fullsize,
            entry.findtext("./modified", ""),
            EntryType(entry.findtext("./type", EntryType.file.value)),
            entry.findtext("./fullfilename", ""),
            entry.findtext("./size", ""),
            entry.findtext("./modifiedepoch", ""),
            bool_opt(entry.findtext("./isroot")),
            bool_opt(entry.findtext("./locked")),
            shared_opt(entry.findtext("./isshared")),
            entry.findtext("./modifiedepochutc", ""),
            entry.findtext("./canupload", "1") == "1",
            entry.findtext("./candownload", "1") == "1",
            entry.findtext("./canrename", "1") == "1",
            entry.findtext("./cansetacls", "0") == "1",
            entry.findtext("./isshareable", "1") == "1",
            entry.findtext("./issyncable", "1") == "1",
            entry.findtext("./isdatasyncable", "1") == "1",
        )

    def getfilelist(
        self,
        path: str,
        sortdir: SortDir = SortDir.ascending,
        start: int = 0,
        limit: int = 1000,
        sortby: SortBy = SortBy.NAME,
        adminproxyuserid: str = "",
    ) -> FileList:
        """
        Returns a list of files/directories in 'path'
        """
        resp = self._api_call(
            "/core/getfilelist",
            {
                "path": path,
                "sortdir": sortdir.value,
                "sortby": sortby.value,
                "start": start,
                "limit": limit,
                "sendaboutinfo": 1,
                "sendmetadatasetinfo": 1,
                "sendcommentinfo": 1,
                "sendfavinfo": 1,
                "adminproxyuserid": adminproxyuserid,
                "includeextrafields": 1,
            },
        )

        meta = resp.find("./meta")
        if meta is None:
            raise ValueError("No meta in server response")

        result = int(meta.findtext("./result", "0"))

        if result != 1:
            raise ValueError("Result at /meta/result not 1 in server response")

        entries: list[FileListEntry] = []

        def bool_opt(txt: Union[None, str]) -> bool:
            if txt is not None and len(txt) > 0:
                return int(txt) > 0
            else:
                return False

        for entry in resp.findall("./entry"):
            entries.append(self._parseEntry(entry))

        return FileList(
            meta.findtext("./parentpath", ""),
            int(meta.findtext("./total", 0)),
            meta.findtext("./realpath", ""),
            bool_opt(meta.findtext("./isroot", "")),
            entries,
        )

    def fileinfo_no_retry(self, path: str) -> FileListEntry:
        """
        Returns information about file/directory 'path'
        """
        resp = self._api_call("/core/fileinfo", {"file": path})

        entry = resp.find("./entry")

        if entry is None:
            raise FileNotFoundError(f"File '{path}' does not exist")

        return self._parseEntry(entry)

    def admin_search(
        self,
        keyword="",
        groupidnin="",
        externalin="",
        status="",
        source="",
        statusnin="",
        start=0,
        end=10,
        admin="",
        policyidnin="",
    ) -> list[ET.Element]:
        """
        Search method to get all users
        """
        resp = self._api_call(
            "/admin/search",
            {
                "op": "search",
                "keyword": keyword,
                "groupidnin": groupidnin,
                "externalin": externalin,
                "status": status,
                "source": source,
                "statusnin": statusnin,
                "start": start,
                "end": end,
                "admin": admin,
                "policyidnin": policyidnin,
            },
        )
        entries = resp.findall("./user")

        if entries is None:
            raise ValueError("No users found")

        return entries

    def fileinfo(self, path: str) -> FileListEntry:
        """
        Returns information about file/directory 'path'. Retries
        """
        if self.retries is None:
            return self.fileinfo_no_retry(path)

        retries = self.retries.new()
        while True:
            try:
                return self.fileinfo_no_retry(path)
            except:
                retries = retries.increment()
                time.sleep(retries.get_backoff_time())

    def fileversions(
        self, filepath: str, filename: str, checksum: bool = True
    ) -> list[FileVersion]:
        """
        Get all the available previous versions of a file
        """
        resp = self._api_call(
            "/core/getversions",
            {
                "filepath": filepath,
                "filename": filename,
                "checksum": 1 if checksum else 0,
            },
        )

        entries: list[FileVersion] = []

        for entry in resp.findall("./version"):
            version = FileVersion(
                versionnumber=entry.findtext("./versionnumber", ""),
                size=entry.findtext("./size", ""),
                how=entry.findtext("./how", ""),
                createdon=entry.findtext("./createdon", ""),
                createdby=entry.findtext("./createdby", ""),
                filename=entry.findtext("./filename", ""),
                sizeinbytes=entry.findtext("./sizeinbytes", ""),
                fileid=entry.findtext("./fileid", ""),
            )

            entries.append(version)

        return entries

    def fileexists_no_retry(self, path: str, caseinsensitive: bool = False) -> bool:
        """
        Returns True if file 'path' exists else False
        """
        resp = self._api_call(
            "/core/fileexists",
            {"file": path, "caseinsensitive": 1 if caseinsensitive else 0},
        )

        return int(resp.findtext("./command/result", "0")) == 1

    def fileexists(self, path: str, caseinsensitive: bool = False) -> bool:
        """
        Returns True if file 'path' exists else False. Retries
        """
        if self.retries is None:
            return self.fileexists_no_retry(path, caseinsensitive)

        retries = self.retries.new()
        while True:
            try:
                return self.fileexists_no_retry(path, caseinsensitive)
            except:
                retries = retries.increment()
                time.sleep(retries.get_backoff_time())

    def waitforfile(self, path: str, maxwaits: float = 30, fsize: int = -1) -> None:
        """
        Waits for file at 'path' to exists for max 'maxwaits' seconds.
        If fsize != -1 also wait for file to have size fsize.
        """
        starttime = time.monotonic()

        while time.monotonic() - starttime < maxwaits:
            if self.fileexists(path):
                if fsize == -1:
                    log.info(
                        f"Found {path} after {(time.monotonic() - starttime)} seconds"
                    )
                    return
                else:
                    info = self.fileinfo(path)
                    if info is not None and info.fullsize == fsize:
                        log.info(
                            f"Found {path} with size {fsize} after {(time.monotonic() - starttime)} seconds"
                        )
                        return

            time.sleep(0.1)

        raise TimeoutError(f"File {path} not found after {maxwaits} seconds")

    def waitforfileremoval(self, path: str, maxwaits: float = 30):
        """
        Waits for file to not exist at 'path' for max 'maxwaits' seconds
        """
        starttime = time.monotonic()

        while time.monotonic() - starttime < maxwaits:
            if not self.fileexists(path):
                return

            time.sleep(0.1)

        raise TimeoutError(f"File {path} not removed after {maxwaits} seconds")

    def downloadfile_no_retry(
        self,
        path: str,
        dstPath: Union[pathlib.Path, str],
        redirect: bool = True,
        progress: Optional[Progress] = None,
    ) -> None:
        """
        Download file at 'path' to local 'dstPath'
        """
        with self.session.get(
            self.url + "/core/downloadfile",
            params={  # type:ignore
                "filepath": path,
                "filename": path.split("/")[-1],
                "redirect": 1 if redirect else 0,
            },
            stream=True,
        ) as resp:
            resp.raise_for_status()
            content_length = int(resp.headers.get("Content-Length", "-1"))
            completed_bytes = 0
            with open(dstPath, "wb") as dstF:
                for chunk in resp.iter_content(128 * 1024):
                    completed_bytes += len(chunk)
                    dstF.write(chunk)
                    if progress is not None:
                        progress.update(completed_bytes, content_length, False)

    def downloadfile(
        self,
        path: str,
        dstPath: Union[pathlib.Path, str],
        redirect: bool = True,
        progress: Optional[Progress] = None,
    ) -> None:
        """
        Download file at 'path' to local 'dstPath'. Retries.
        """
        if self.retries is None:
            return self.downloadfile_no_retry(path, dstPath, redirect, progress)

        retries = self.retries
        while True:
            try:
                self.downloadfile_no_retry(path, dstPath, redirect, progress)
                return
            except:
                retries = retries.increment()
                time.sleep(retries.get_backoff_time())

    def downloadfolder(self, path: str, dstPath: Union[pathlib.Path, str]) -> None:
        """
        Recursively download files/directories at 'path'
        to local path 'dstPath'
        """
        files = self.getfilelist(path)

        for file in files.entries:
            dstFn = Path(dstPath) / file.name
            if file.type == EntryType.dir:
                if not dstFn.is_dir():
                    dstFn.mkdir()

                self.downloadfolder(path + "/" + file.name, dstFn)
            else:
                self.downloadfile(path + "/" + file.name, dstFn)

    def deletefile(self, path: str, adminproxyuserid: Optional[str] = None):
        """
        Delete file at 'path'
        """
        dir = "/".join(path.split("/")[:-1])
        name = path.split("/")[-1]

        resp = self._api_call(
            "/core/deletefile",
            {"path": dir, "name": name, "adminproxyuserid": adminproxyuserid},
        )
        self._raise_exception_from_command(resp)

    def upload_bytes(
        self,
        data: bytes,
        serverpath: str,
        datemodified: datetime.datetime = datetime.datetime.now(),
        progress: Optional[Progress] = None,
    ) -> None:
        """
        Upload bytes 'data' to server at 'serverpath'.
        """
        self.upload(BufferedReader(BytesIO(data)), serverpath, datemodified, progress=progress)  # type: ignore

    def upload_str(
        self,
        data: str,
        serverpath: str,
        datemodified: datetime.datetime = datetime.datetime.now(),
        progress: Optional[Progress] = None,
    ) -> None:
        """
        Upload str 'data' UTF-8 encoded to server at 'serverpath'.
        """
        self.upload_bytes(
            data.encode("utf-8"), serverpath, datemodified, progress=progress
        )

    def upload_file(
        self,
        localpath: pathlib.Path,
        serverpath: str,
        datemodified: datetime.datetime = datetime.datetime.now(),
        adminproxyuserid: Optional[str] = None,
        progress: Optional[Progress] = None,
    ) -> None:
        """
        Upload file at 'localpath' to server at 'serverpath'.
        """
        with open(localpath, "rb") as uploadf:
            self.upload(
                uploadf,
                serverpath,
                datemodified,
                adminproxyuserid=adminproxyuserid,
                progress=progress,
            )

    def _serverdatetime(self, dt: datetime.datetime):
        return "%04d-%02d-%02d %02d:%02d:%02d" % (
            dt.year,
            dt.month,
            dt.day,
            dt.hour,
            dt.minute,
            dt.second,
        )

    def upload(
        self,
        uploadf: BufferedReader,
        serverpath: str,
        datemodified: datetime.datetime,
        adminproxyuserid: Optional[str] = None,
        progress: Optional[Progress] = None,
    ) -> None:
        """
        Upload seekable stream at uploadf to server at 'serverpath'
        """
        dir = "/".join(serverpath.split("/")[:-1])
        name = serverpath.split("/")[-1]

        assert uploadf.seekable(), "Upload stream must be seekable"

        data_marker = b"DATA_MARKER"

        class FileSlice(BufferedReader):
            def __init__(
                self, stream: BufferedReader, start: int, size: int, envelope: bytes
            ):
                super().__init__(stream)  # type: ignore
                self.start = start
                self.end = start + size
                self.pos = start
                self.envelope_prefix = envelope[: envelope.index(data_marker)]
                self.envelope_read = 0
                self.envelope_suffix = envelope[
                    envelope.index(data_marker) + len(data_marker) :
                ]
                super().seek(start)

            def read(self, size=-1):
                # Read the envelope first
                if self.pos == self.end and self.envelope_read < len(
                    self.envelope_suffix
                ) + len(self.envelope_prefix):
                    if size < 0 or size > len(self.envelope_suffix):
                        size = len(self.envelope_suffix)
                    data = self.envelope_suffix[
                        self.envelope_read
                        - len(self.envelope_prefix) : self.envelope_read
                        - len(self.envelope_prefix)
                        + size
                    ]
                    self.envelope_read += len(data)
                    return data
                if self.pos >= self.end:
                    return b""
                # Read then end of the envelope
                if self.pos == self.start and self.envelope_read < len(
                    self.envelope_prefix
                ):
                    if size < 0 or size > len(self.envelope_prefix):
                        size = len(self.envelope_prefix)
                    data = self.envelope_prefix[
                        self.envelope_read : self.envelope_read + size
                    ]
                    self.envelope_read += len(data)
                    return data
                # Read the file
                max_read = self.end - self.pos
                if size < 0:
                    size = min(256 * 1024, max_read)
                else:
                    size = min(size, max_read)
                data = super().read(size)
                self.pos += len(data)
                if progress is not None:
                    progress.update(self.pos, data_size, False)
                return data

            def __len__(self) -> int:
                return (
                    self.end
                    - self.start
                    + len(self.envelope_prefix)
                    + len(self.envelope_suffix)
                )

            def __iter__(self):
                return self

            def tell(self) -> int:
                if self.pos == self.start:
                    return 0
                if self.pos == self.end:
                    return len(self)
                return self.pos - self.start + self.envelope_read

            def seek(self, offset: int, whence: int = 0) -> int:
                if whence == SEEK_SET:  # from the start
                    self.pos = self.start + offset
                elif whence == SEEK_CUR:  # from the current position
                    self.pos += offset
                elif whence == SEEK_END:  # from the end
                    self.pos = self.end + offset
                else:
                    raise ValueError(f"Invalid value for whence: {whence}")

                if self.pos < self.start:
                    self.pos = self.start
                elif self.pos > self.end:
                    self.pos = self.end

                if self.pos == self.start:
                    self.envelope_read = 0

                super().seek(self.pos)

                return self.pos

            def close(self):
                pass

        slice_size = 20 * 1024 * 1024  # 20 MiB
        pos = 0

        uploadf.seek(0, 2)
        data_size = uploadf.tell()

        if data_size == 0:
            # Special case for empty files
            params = {
                "appname": "explorer",
                "path": dir,
                "offset": 0,
                "complete": 1,
                "filename": name,
                "filesize": 0,
                "date": self._serverdatetime(datemodified),
                "adminproxyuserid": adminproxyuserid,
            }
            params_str = urlencode(params)

            if params_str.find("%2FSHARED%2F%21"):
                params_str = params_str.replace(
                    "%%2FSHARED%2F%21", "%2FSHARED%2F!"
                )  # WEBUI DOES NOT ENCODE THE !

            resp = self.session.post(
                self.url + "/core/upload?" + params_str,
                files={"file_contents": (name, b"")},
            )

            resp.raise_for_status()

            if resp.text != "OK":
                log.warning(f"Upload error. Response: {resp.text}")
                raise ServerError("", resp.text)

            return

        rf = RequestField(name="file_contents", data=data_marker, filename=name)
        rf.make_multipart()

        envelope, content_type = encode_multipart_formdata([rf])

        headers = {"Content-type": content_type}

        while pos < data_size or (data_size == 0 and pos == 0):

            curr_slice_size = min(slice_size, data_size - pos)
            complete = 0 if pos + curr_slice_size < data_size else 1

            params = {
                "appname": "explorer",
                "path": dir,
                "offset": pos,
                "complete": complete,
                "filename": name,
                "date": self._serverdatetime(datemodified),
                "adminproxyuserid": adminproxyuserid,
            }

            if data_size is not None:
                params["filesize"] = data_size

            params_str = urlencode(params)

            if params_str.find("%2FSHARED%2F%21"):
                params_str = params_str.replace(
                    "%%2FSHARED%2F%21", "%2FSHARED%2F!"
                )  # WEBUI DOES NOT ENCODE THE !

            resp = self.session.post(
                self.url + "/core/upload?" + params_str,
                data=FileSlice(uploadf, pos, curr_slice_size, envelope),
                headers=headers,
                stream=True,
            )

            resp.raise_for_status()

            if resp.text != "OK":
                log.warning(f"Upload error. Response: {resp.text}")
                raise ServerError("", resp.text)

            pos += curr_slice_size

            if progress is not None:
                progress.update(pos, data_size, True)

    def share(self, path: str, adminproxyuserid: str = "") -> FCShare:
        """
        Share 'path'
        """
        resp = self._api_call(
            "/core/addshare",
            {
                "sharelocation": path,
                "adminproxyuserid": adminproxyuserid,
                "sharename": path.split("/")[:-1],
            },
        )

        shareid = resp.findtext("./share/shareid", "")

        if not shareid:
            msg = resp.findtext("./meta/message", "")
            if msg:
                raise ServerError("", msg)
            else:
                raise ServerError("", "No shareid in response")

        return FCShare(
            shareid,
            resp.findtext("./share/sharename", ""),
            resp.findtext("./share/sharelocation", ""),
            str_to_bool(resp.findtext("./share/allowpublicaccess", "")),
            str_to_bool(resp.findtext("./share/allowpublicupload", "")),
            str_to_bool(resp.findtext("./share/allowpublicviewonly", "")),
            str_to_bool(resp.findtext("./share/allowpublicuploadonly", "")),
        )

    def getshareforpath(self, path: str, adminproxyuserid: str = "") -> FCShare:
        """
        Share 'path'
        """
        resp = self._api_call(
            "/core/getshareforpath",
            {"path": path, "adminproxyuserid": adminproxyuserid},
        )

        return FCShare(
            resp.findtext("./share/shareid", ""),
            resp.findtext("./share/sharename", ""),
            resp.findtext("./share/sharelocation", ""),
            str_to_bool(resp.findtext("./share/allowpublicaccess", "")),
            str_to_bool(resp.findtext("./share/allowpublicupload", "")),
            str_to_bool(resp.findtext("./share/allowpublicviewonly", "")),
            str_to_bool(resp.findtext("./share/allowpublicuploadonly", "")),
        )

    def setallowpublicaccess(
        self,
        share: FCShare,
        allowpublicaccess: bool,
        allowpublicviewonly: bool = False,
        allowpublicuploadonly: bool = False,
        allowpublicupload: bool = False,
        sharepassword: str = "",
        adminproxyuserid: Optional[str] = None,
    ) -> None:
        """
        Set access permissions to share
        """
        resp = self._api_call(
            "/core/setallowpublicaccess",
            {
                "shareid": share.shareid,
                "allowpublicaccess": 1 if allowpublicaccess else 0,
                "allowpublicviewonly": 1 if allowpublicviewonly else 0,
                "allowpublicuploadonly": 1 if allowpublicuploadonly else 0,
                "allowpublicupload": 1 if allowpublicupload else 0,
                "sharepassword": sharepassword,
                "adminproxyuserid": adminproxyuserid,
            },
        )
        self._raise_exception_from_command(resp)

    def adduserstoshare(
        self,
        share: FCShare,
        users: list[str],
        sendemail: bool = False,
        adminproxyuserid: Optional[str] = None,
    ) -> None:
        """
        Allow users access to share
        """
        resp = self._api_call(
            "/core/adduserstoshare",
            {
                "shareid": share.shareid,
                "users": ",".join(users),
                "sendemail": 1 if sendemail else 0,
                "adminproxyuserid": adminproxyuserid if adminproxyuserid else "",
            },
        )

        self._raise_exception_from_command(resp)

    def createfolder(
        self,
        path: str,
        subpath: Optional[str] = None,
        adminproxyuserid: Optional[str] = None,
    ) -> None:
        """
        Create folder at 'path'
        """
        dir = "/".join(path.split("/")[:-1])
        name = path.split("/")[-1]

        payload = {
            "name": name,
            "path": dir,
            "adminproxyuserid": adminproxyuserid,
        }
        if subpath is not None:
            payload["subpath"] = subpath

        resp = self._api_call(
            "/core/createfolder",
            payload,
        )

        self._raise_exception_from_command(resp)

    def renamefile(self, path: str, name: str, newname) -> None:
        """
        Rename a file
        """
        resp = self._api_call(
            "/core/renamefile", {"path": path, "name": name, "newname": newname}
        )
        self._raise_exception_from_command(resp)

    def get_username(self):
        """
        Return the username/profile name specified at init
        """
        return self.username

    def setuseraccessforshare(
        self,
        share: Optional[FCShare],
        userid: str,
        allowmanage: bool,
        allowwrite: bool,
        allowdownload: bool,
        allowshare: bool,
        allowsync: bool,
        disallowdelete: bool,
        adminproxyuserid: Optional[str] = None,
    ) -> None:
        """
        Set user permissions for share
        """
        resp = self._api_call(
            "/core/setuseraccessforshare",
            {
                "shareid": share.shareid if share else "false",
                "userid": userid,
                "allowmanage": "true" if allowmanage else "false",
                "write": "true" if allowwrite else "false",
                "download": "true" if allowdownload else "false",
                "share": "true" if allowshare else "false",
                "sync": "true" if allowsync else "false",
                "disallowdelete": "true" if disallowdelete else "false",
                "adminproxyuserid": adminproxyuserid if adminproxyuserid else "",
            },
        )
        self._raise_exception_from_command(resp)

    def getusersforshare(self, share: FCShare) -> list[FCShareUser]:
        """
        Returns a list of users that are added explicitly to the share
        """
        resp = self._api_call(
            "/core/getusersforshare",
            {"shareid": share.shareid},
        )
        entries: list[FCShareUser] = []

        for entry in resp.findall("./user"):
            user = FCShareUser(
                name=entry.findtext("./name", ""),
                read=entry.findtext("./read") == "true",
                write=entry.findtext("./write") == "true",
                sync=entry.findtext("./sync") == "true",
                share=entry.findtext("./share") == "true",
                download=entry.findtext("./download") == "true",
                disallowdelete=entry.findtext("./disallowdelete") == "true",
                allowmanage=entry.findtext("./allowmanage") == "true",
            )
            entries.append(user)

        return entries

    def wait_for_user_to_have_permission_in_share(
        self,
        share: FCShare,
        user: str = "",
        permission: str = "",
        permission_flag: bool = False,
        max_wait: int = 30,
    ) -> None:
        """
        Waits for a max_wait period of time unless the user specified has the permission specified = permission_flag
        """

        start_time = time.monotonic()

        while time.monotonic() - start_time < max_wait:
            users_in_share = self.getusersforshare(share)

            if users_in_share != None and any(
                item["name"] == user and item[permission] == permission_flag
                for item in users_in_share
            ):
                return

            time.sleep(0.1)

        raise TimeoutError("User does not have permission in share")

    def lock(
        self, path: str, readlock: bool = False, relative_expiration: int = 0
    ) -> None:
        """
        Lock file at 'path'
            str: path to file
            readlock: said option
            expiration: lock expiry time in seconds
        """
        resp = self._api_call(
            "/core/lock",
            {
                "path": path,
                "readlock": 1 if readlock else 0,
                "relative_expiration": relative_expiration,
            },
        )
        self._raise_exception_from_command(resp)

    def unlock(self, path: str) -> None:
        """
        Unlock file at 'path'
        """
        resp = self._api_call("/core/unlock", {"path": path})
        self._raise_exception_from_command(resp)

    def getfilelockinfo(self, path: str) -> FileLockInfo:
        """
        Get information about lock at 'path'
        """
        resp = self._api_call("/core/getfilelockinfo", {"path": path})

        return FileLockInfo(
            resp.findtext("./filelockinfo/locked", "0") == "1",
            resp.findtext("./filelockinfo/readlock", "0") == "1",
            resp.findtext("./filelockinfo/lockedby", ""),
        )

    def waitforlock(self, path: str, maxwaits: float = 30):
        """
        Wait for file to get locked at 'path' for max 'maxwaits' seconds
        """
        starttime = time.monotonic()

        while time.monotonic() - starttime < maxwaits:
            li = self.getfilelockinfo(path)
            if li != None and li.locked:
                return

            time.sleep(0.1)

        raise TimeoutError(f"File {path} not locked after {maxwaits} seconds")

    def waitforlockrelease(self, path: str, maxwaits: float = 30) -> None:
        """
        Wait for file to get unlocked at 'path' for max 'maxwaits' seconds
        """
        starttime = time.monotonic()

        while time.monotonic() - starttime < maxwaits:
            li = self.getfilelockinfo(path)
            if li != None and not li.locked:
                return

            time.sleep(0.1)

        raise TimeoutError(f"File {path} not unlocked after {maxwaits} seconds")

    def copyfile(self, src_path: str, dst_path: str) -> None:
        """
        Copy file/directory
        """
        dir = "/".join(src_path.split("/")[:-1])
        src_name = src_path.split("/")[-1]
        dst_dir = "/".join(dst_path.split("/")[:-1])
        dst_name = dst_path.split("/")[-1]

        resp = self._api_call(
            "/app/explorer/copyfile",
            {"name": src_name, "path": dir, "copyto": dst_dir, "copytoname": dst_name},
        )
        self._raise_exception_from_command(resp)

    def movefile(self, src_path: str, dst_path: str) -> None:
        """
        Move file/directory
        """
        resp = self._api_call(
            "/app/explorer/renameormove",
            {"fromname": src_path, "toname": dst_path, "overwrite": 0},
        )
        self._raise_exception_from_command(resp)

    def movefile_retry(self, src_path: str, dst_path: str) -> None:
        """
        Move file/directory. Retries.
        """
        if self.retries is None:
            return self.movefile(src_path, dst_path)

        retries = self.retries
        while True:
            try:
                self.movefile(src_path, dst_path)
                return
            except:
                retries = retries.increment()
                time.sleep(retries.get_backoff_time())

    def getrmcclients(self) -> list[RMCClient]:
        """
        Returns a list of clients that need approval
        """
        resp = self._api_call(
            "/core/getrmcclients", {"userid": self.username, "start": 0, "end": 1000000}
        )

        entries: list[RMCClient] = []

        for entry in resp.findall("./rmc_client"):

            ne = RMCClient(
                rid=entry.findtext("./rid", ""),
                remote_client_id=entry.findtext("./remote_client_id", ""),
                remote_client_disp_name=entry.findtext("./remote_client_disp_name", ""),
                remote_client_last_login=entry.findtext(
                    "./remote_client_last_login", ""
                ),
                remote_client_status=int(
                    entry.findtext("./remote_client_status", "-1")
                ),
                remote_client_status_message=entry.findtext(
                    "./remote_client_status_message", ""
                ),
            )
            entries.append(ne)

        return entries

    def approvedeviceaccess(self, remote_client_id: str) -> str:
        """
        Approve device and return device authentication code
        """
        resp = self._api_call(
            "/core/approvedeviceaccess",
            {"remote_client_id": remote_client_id},
        )

        self._raise_exception_from_command(resp)

        return resp.findtext("./command/message", "")

    def getteamfolderinfo(self) -> TeamFolderInfo:
        """
        Returns Team Folder information
        """
        resp = self._api_call("/admin/getteamfolderproperties", {})

        tf_info = TeamFolderInfo(
            resp.findtext("./teamfolderproperty/enabled", "0") == "1",
            resp.findtext("./teamfolderproperty/username", ""),
            resp.findtext("./teamfolderproperty/aclenabled", "0") == "1",
        )

        tf_list = self.getfilelist(
            f"/{tf_info.teamfolderaccount}", adminproxyuserid=self.username
        )
        tf_info.teamfolderpath = tf_list.entries[0].path  # type:ignore

        return tf_info

    def getnetworkfolderinfo(self) -> NetworkFolderInfo:
        """
        Returns a network folder information
        """
        resp = self.getfilelist("/EXTERNAL")
        return NetworkFolderInfo(
            resp.entries[0].path,  # type: ignore
        )

    def getsyncfolderlist(self, paths=list[str]()) -> list[SyncFolder]:
        """
        Returns list of syncable folders and their current update version
        """
        params = {"v": "1", "skipsyncwithevents": "1", "count": len(paths)}
        idx = 1
        for path in paths:
            params[f"path{idx}"] = path
            idx += 1

        resp = self._api_call("/app/sync/getsyncfolderlist", params)

        sync_folders: list[SyncFolder] = []

        for entry in resp.findall("./syncfolder"):

            status_set = entry.findtext("./statusset")

            assert status_set is not None

            update_version = int(status_set.split(";")[0].split(",")[1])

            ne = SyncFolder(entry.findtext("./name", ""), update_version)
            sync_folders.append(ne)

        return sync_folders

    def getsyncfolder(self, path: str) -> SyncFolder:
        """
        Returns current update version and path for path
        """
        paths = list[str]()
        if path.startswith("/EXTERNAL/"):
            ns = path.index("/", 10)
            paths.append(path[:ns])

        syncfolderlist = self.getsyncfolderlist(paths)

        for syncfolder in syncfolderlist:

            if path.startswith(syncfolder.path):
                return syncfolder

        raise ValueError("Path not found in sync folder list")

    def getsyncdelta(
        self, sync_folder: SyncFolder, with_permissions: bool = True
    ) -> list[SyncDeltaItem]:
        """
        Returns sync delta items for path since updateversion
        """
        resp = self._api_call(
            "/app/sync/getsyncdelta",
            {
                "friendly": "Python fcserver",
                "name": sync_folder.path,
                "path": sync_folder.path,
                "status": f"server,{sync_folder.update_version};",
                "permissions": "1" if with_permissions else "0",
            },
        )

        sync_delta: list[SyncDeltaItem] = []

        for entry in resp.findall("./record"):

            entry_type = int(entry.findtext("./type", "1"))

            ne = SyncDeltaItem(
                EntryType.dir if entry_type == 0 else EntryType.file,
                int(entry.findtext("./size", "0")),
                entry.findtext("./modified", ""),
                entry.findtext("./name", ""),
                entry.findtext("./fullpath", ""),
                entry.findtext("./flags", ""),
                int(entry.findtext("./isdeleted", "0")) == 1,
                int(entry.findtext("./updateversion", 0)),
                int(entry.findtext("./candownload", "0")) == 1,
                int(entry.findtext("./canupload", "0")) == 1,
                int(entry.findtext("./canrename", "0")) == 1,
            )
            sync_delta.append(ne)

        return sync_delta

    def waitforsyncdeltaitem(
        self,
        syncfolder: SyncFolder,
        find_path: str,
        find_size: int,
        find_isdeleted: bool,
        maxwaits: int = 30,
    ) -> None:
        """
        Wait for sync delta item at path
        """

        starttime = time.monotonic()

        while time.monotonic() - starttime < maxwaits:

            items = self.getsyncdelta(syncfolder, with_permissions=False)

            if items is None:
                time.sleep(1)
                continue

            for item in items:

                if (
                    item.fullpath == find_path
                    and item.size == find_size
                    and item.isdeleted == find_isdeleted
                ):
                    return

                syncfolder.update_version = max(
                    item.updateversion, syncfolder.update_version
                )

            time.sleep(0.1)

        raise TimeoutError(f"Sync delta item not found after {maxwaits} seconds")

    def admin_getrmcclients(
        self, username: str = "", end_int: int = 10000, sortdir: str = "-1"
    ) -> list[RMCClient]:
        """
        Returns a list of clients from admin
        """
        resp = self._api_call(
            "/admin/getrmcclients",
            {
                "userid": username if username != "" else self.username,
                "start": 0,
                "end": end_int,
                "sortfield": "remote_client_last_login",
                "sortdir": sortdir,
            },
        )

        entries: list[RMCClient] = []

        for entry in resp.findall("./rmc_client"):
            client = RMCClient(
                rid=entry.findtext("./rid", ""),
                remote_client_id=entry.findtext("./remote_client_id", ""),
                remote_client_disp_name=entry.findtext("./remote_client_disp_name", ""),
                remote_client_last_login=entry.findtext(
                    "./remote_client_last_login", ""
                ),
                remote_client_status=int(
                    entry.findtext("./remote_client_status", "-1")
                ),
                remote_client_status_message=str(
                    entry.findtext("./remote_client_status_message", "")
                ),
            )
            entries.append(client)

        return entries

    def admin_adduser(
        self,
        username: str = "",
        password: str = "",
        email: str = "",
        display_name: str = "",
        authtype: str = "0",  # full user
        status: str = "1",  # active
        istfuser: str = "0",  # not teamfolder user
        sendpw: str = "0",
        sendemail: str = "0",
    ) -> None:
        """
        Returns a newly server-created user credenial
        """
        resp = self._api_call(
            "/admin/adduser",
            {
                "op": "adduser",
                "username": username,
                "displayname": username if display_name == "" else display_name,
                "email": email,
                "password": password,
                "authtype": authtype,
                "status": status,
                "isteamfolderuser": istfuser,
                "sendpwdasplaintext": sendpw,
                "sendapprovalemail": sendemail,
            },
        )

        self._raise_exception_from_command(resp)

    def admin_deleteuser(self, profile: str) -> None:
        """
        Deletes the user from filecloud
        on server 23.241 can use also /admin/deleteuser
        """
        resp = self._api_call(
            "/admin",
            {
                "op": "deleteuser",
                "profile": profile,
            },
        )
        self._raise_exception_from_command(resp)

    def admin_addrmccommand(
        self, remote_client_id: str, remote_command_id: str, message: str
    ) -> None:
        """
        Add a message to the client based on command ID like:
            10000 - display message
            10001 - remote wipe and block login
            10002 - block login
        """
        resp = self._api_call(
            "/admin/addrmccommand",
            {
                "remote_client_id": remote_client_id,
                "remote_command_id": remote_command_id,
                "message": message,
            },
        )

        self._raise_exception_from_command(resp)

    def admin_removermcclient(self, remote_client_id: str):
        """
        Removes the commands for the device
        """
        resp = self._api_call(
            "/admin/removermcclient",
            {
                "remote_client_id": remote_client_id,
            },
        )

        self._raise_exception_from_command(resp)

    def admin_getusersforpolicy(
        self, policy_id: str = ""
    ) -> Optional[list[PolicyUser]]:
        """
        Returns a list of users assigned to policy
        """
        resp = self._api_call(
            "/admin/getusersforpolicy",
            {"policyid": policy_id},
        )
        entries: list[PolicyUser] = []

        for entry in resp.findall("./user"):
            user = PolicyUser(
                username=entry.findtext("./username", ""),
                status=int(entry.findtext("./status", "1")),
                adminstatus=int(entry.findtext("./adminstatus", "0")),
                authtype=int(entry.findtext("./authtype", "0")),
            )
            entries.append(user)

        return entries

    def admin_assignpolicytouser(self, username: str, policyid: str) -> None:
        """
        Assign policy to a user
        """
        resp = self._api_call(
            "/admin/assignpolicytouser",
            {
                "username": username,
                "policyid": policyid,
            },
        )
        self._raise_exception_from_command(resp)

    def admin_resetpolicyforuser(self, username: str) -> None:
        """
        Resets policy for user
        """
        resp = self._api_call(
            "/admin/resetpolicyforuser",
            {
                "username": username,
            },
        )

        self._raise_exception_from_command(resp)

    def get_config_settings(self, config: list[str]) -> None:
        """
        Retrieve Filecloud configuration settings. The config list should
        contain FC configuration keys.
        Args:
            config: Dictionary containing FC config keys and values
        """
        try:
            count = len(config)
        except (ValueError, TypeError):
            count = 0

        config_opts = []
        for i in range(count):
            param_key = f"param{i}"
            config_opts[param_key] = config[i]

        resp = self._api_call(
            "/admin/setconfigsetting",
            {
                "count": str(len(config_opts)),
                **{f"param{i}": value for i, value in enumerate(config_opts)},
            },
        )

        settings = ServerSettings(resp)
        return settings

    def set_config_setting(self, config_name: str, config_val: str) -> None:
        """
        Sets a server config setting via admin
        """
        resp = self._api_call(
            "/admin/setconfigsetting",
            {"count": 1, "param0": config_name, "value0": config_val},
        )

        self._raise_exception_from_command(resp)

    def admin_addnewuser(
        self,
        username: str,
        email: str,
        password: str,
        authtype: str = "0",
        status: int = 1,
    ) -> None:
        """
        Creates a new user to the server
        # Todo: refactor with user factory ticket changes
        """
        resp = self._api_call(
            "/admin/adduser",
            {
                "username": username,
                "displayname": username,
                "email": email,
                "password": password,
                "authtype ": authtype,  # 0 for default auth and 1 for AD
                "status": status,  # full(1), guest(0), external(3) or disabled user(2)
            },
        )

        self._raise_exception_from_command(resp)

    def admin_logout(self) -> None:
        """
        Perform admin logout
        """
        resp = self._api_call(
            "/admin/logout",
            {
                "op": "logout",
            },
        )
        self._raise_exception_from_command(resp)

    def add_policy(self, policy_name: str, is_default=False) -> None:
        """Add a policy"""
        payload = {
            "op": "addpolicy",
            "policyname": policy_name,
            "isdefault": is_default,
        }

        resp = self._api_call(
            "/admin/addpolicy",
            payload,
        )

        self._raise_exception_from_command(resp)

    def update_policy(self, policy_id: str, config: Dict) -> None:
        """Update specific policy"""
        payload = {
            "op": "updatepolicy",
            "policyid": policy_id,
        }

        payload = payload | config

        resp = self._api_call(
            "/admin/updatepolicy",
            payload,
        )

        self._raise_exception_from_command(resp)

    def assign_policy_to_user(self, username: str, policy_id: str) -> None:
        """Add user to specific policy"""
        resp = self._api_call(
            "/admin/assignpolicytouser",
            {"op": "assignpolicytouser", "policyid": policy_id, "username": username},
        )
        self._raise_exception_from_command(resp)

    def get_all_policies(
        self, start: int = 0, limit: int = 1000, policynamefilter: Optional[str] = None
    ) -> PolicyList | None:
        """List all policies"""
        resp = self._api_call(
            "/admin/getallpolicies",
            {
                "op": "getallpolicies",
                "start": start,
                "limit": limit,
                "policynamefilter": policynamefilter,
            },
        )
        policies = PolicyList(resp)
        return policies

    def admin_rm_policy(self, policy_id: str) -> None:
        """Remove specific policy"""
        resp = self._api_call(
            "/admin/removepolicy",
            {
                "op": "removepolicy",
                "policyid": policy_id,
            },
        )
        self._raise_exception_from_command(resp)

    def admin_get_default_policy(self) -> PolicyList:
        """Get global policy"""
        resp = self._api_call("/admin/getdefaultpolicy", {"op": "getdefaultpolicy"})

        return PolicyList(resp)

    def get_effective_policy_for_user(self, username: str) -> PolicyList:
        """List all policies"""
        resp = self._api_call(
            "/admin/geteffectivepolicyforuser",
            {"op": "geteffectivepolicyforuser", "username": username},
        )

        self._raise_exception_from_command(resp)

        eff_policy = PolicyList(resp)
        return eff_policy

    def get_teamfolder_properties(self) -> TeamFolderInfo:
        """Get team folder properties"""
        resp = self._api_call(
            "/admin/getteamfolderproperties",
            {"op": "getteamfolderproperties"},
        )

        if resp is None:
            raise ServerError("0", "Team folder properties cannot be obtained")

        tf_props = TeamFolderInfo(
            teamfolderenabled=bool(resp.findtext("./teamfolderproperty/enabled", "0")),
            teamfolderaccount=str(resp.findtext("./teamfolderproperty/username", "0")),
            aclenabled=bool(resp.findtext("./teamfolderproperty/aclenabled", "0")),
        )
        return tf_props

    def get_user_status(self, username: str) -> UserStatus:
        """Retrieve the status of a user with retries.
        Returns the status number or UserStatus.UNKNOWN if the status could not be retrieved.
        """
        max_retries = 3
        retry_delay = 0.1
        retries = 0
        while retries < max_retries:
            try:
                resp = self._api_call(
                    "/admin/getuser",
                    {"op": "getuser", "username": username},
                )
                status = resp.findtext("./user/status")
                if status is not None:
                    try:
                        return UserStatus(int(status))
                    except ValueError:
                        log.error(f"Invalid status value for user {username}: {status}")
                        return UserStatus.UNKNOWN
                else:
                    log.error(f"No status found for user {username} in the response.")
                    return UserStatus.UNKNOWN
            except Exception as e:
                log.exception(
                    f"Failed to get user {username} details (Attempt {retries + 1}/{max_retries}): {e}"
                )
                retries += 1
                if retries < max_retries:
                    time.sleep(retry_delay)
        return UserStatus.UNKNOWN

    def set_license_xml(self, license_file: Path) -> None:
        """Set a license"""
        license_fullpath = license_file.resolve()

        self._admin_api_call_setlicense(
            "/admin/setlicensexml",
            params={"op": "setlicensexml"},
            files={"file": ("license.xml", open(license_fullpath, "rb"), "text/xml")},
        )

    def add_acl_entry(
        self,
        path: str,
        type: AclEntryType,
        value: str,
        perm: AclPermissions,
        flag="allow",
        adminproxyuserid: Optional[str] = None,
    ) -> None:
        """
        Add an ACL entry to a path
        """
        resp = self._api_call(
            "/core/addaclentry",
            params={
                "path": path,
                "type": type.value,
                "value": value,
                "perm": str(perm),
                "flag": flag,
                "adminproxyuserid": adminproxyuserid if adminproxyuserid else "",
            },
        )

        self._raise_exception_from_command(resp)

    def deleteaclentry(self, path: str, value: AclPermissions, type="user") -> None:
        """
        Add an ACL entry to a path
        """
        resp = self._api_call(
            "/core/deleteaclentry",
            params={"path": path, "type": type, "value": value},
        )
        self._raise_exception_from_command(resp)

    def admin_getgroups(
        self,
        start=0,
        limit=10,
        sortfield="",
        sortdir="1",
        everyone: Optional[bool] = False,
    ) -> Union[
        tuple[Optional[str], Optional[str]], list[tuple[Optional[str], Optional[str]]]
    ]:
        """
        List all user groups
        If required, obtain the EVERYONE group only
        """
        resp = self._api_call(
            "/admin/getgroups",
            {
                "op": "getgroups",
                "start": start,
                "limit": limit,
                "sortfield": sortfield,
                "sortdir": sortdir,
            },
        )

        group_list = list[tuple[Optional[str], Optional[str]]]()

        for group_elem in resp:  # type:ignore
            group_id = None
            group_name = None

            if group_elem is not None:
                group_id_elem = group_elem.findtext("groupid")
                group_name_elem = group_elem.findtext("groupname")

                if group_id_elem == None:
                    continue

                if group_id_elem is not None:
                    group_id = group_id_elem  # type:ignore

                if group_name_elem is not None:
                    group_name = group_name_elem  # type:ignore

            if everyone and group_name == "EVERYONE":
                # Return the group immediately.
                return (group_name, group_id)

            group_list.append((group_name, group_id))

        return group_list

    def admin_createnewgroup(self, groupname: str):
        """List all policies"""
        resp = self._api_call(
            "/admin/addgroup",
            {"op": "addgroup", "groupname": groupname},
        )

        if int(resp.findtext("./group/groupname", "0")) != 1:
            raise ServerError("", "Failed to create group")

    def admin_groupisinshare(
        self,
        share: FCShare,
        group_id: str,
        adminproxyuserid: str,
    ) -> None:
        """
        Set access permissions to share
        """

        resp = self._api_call(
            "/app/websharepro/getgroupaccessforshare",
            {
                "shareid": share.shareid,
                "adminproxyuserid": adminproxyuserid,
            },
        )

        groupid_text = resp.findtext("./group/groupid")
        if not groupid_text or groupid_text != group_id:
            raise ServerError(
                "", f"group {group_id} is not in shared folder '{str(share)}'"
            )

    def admin_addgrouptoshare(
        self, share: FCShare, groupid: str, adminproxyuserid: str = ""
    ) -> None:
        """
        Allow group access to share
        """
        resp = self._api_call(
            "/core/addgrouptoshare",
            {
                "shareid": share.shareid,
                "groupid": groupid,
                "adminproxyuserid": adminproxyuserid,
            },
        )
        self._raise_exception_from_command(resp)

    def admin_addgrouptoexternal(self, externalid, groupid, writemode="1"):
        """
        Allow group access to external
        """
        resp = self._api_call(
            "/admin/addgrouptoexternal",
            {"groupid": groupid, "externalid": externalid, "writemode": writemode},
        )

        self._raise_exception_from_command(resp)

    def admin_getexternals(self, start=0, end=10, filter="") -> ET.Element:
        """
        Get all externals
        """
        resp = self._api_call(
            "/admin/getexternals",
            {"start": start, "end": end, "filter": filter},
        )

        return resp

    def admin_addmembertogroup(self, groupid: str, username: str) -> None:
        """
        Add user to group
        """
        resp = self._api_call(
            "/admin/addmembertogroup",
            {
                "groupid": groupid,
                "userid": username,
            },
        )
        self._raise_exception_from_command(resp)

    def admin_setgroupaccessforshare(
        self,
        share: Optional[FCShare],
        groupid: str,
        adminproxyuserid: str = "",
    ) -> None:
        """
        Set all user permissions for share
        """
        resp = self._api_call(
            "/app/websharepro/setgroupaccessforshare",
            {
                "shareid": share.shareid if share else "false",
                "groupid": groupid,
                "write": "true",
                "download": "true",
                "share": "true",
                "sync": "true",
                "disallowdelete": "false",
                "adminproxyuserid": adminproxyuserid,
            },
        )
        self._raise_exception_from_command(resp)

    def admin_set_teamfolder_user(self, username: str) -> None:
        """
        Add user to group
        """
        resp = self._api_call(
            "/admin/setteamfolderuser",
            {
                "op": "setteamfolderuser",
                "username": username,
            },
        )
        self._raise_exception_from_command(resp)

    def admin_addexternal(
        self,
        externalname: Optional[str],
        type: Optional[str] = None,
        location: Optional[str] = None,
        automount: Optional[str] = None,
        automount_type: Optional[str] = None,
        automuntparam1: Optional[str] = None,
        perm: Optional[str] = None,
        bucket: Optional[str] = None,
        region: Optional[str] = None,
        key: Optional[str] = None,
        secret: Optional[str] = None,
        endpoint: Optional[str] = None,
        toplevelprefix: Optional[str] = None,
        enableenc: Optional[str] = None,
        enctype: Optional[str] = None,
        kmsid: Optional[str] = None,
        useiamrole: Optional[str] = None,
        container: Optional[str] = None,
        accountkey: Optional[str] = None,
        accountname: Optional[str] = None,
    ) -> ET.Element:
        """
        Add external to server
        """
        resp = self._api_call(
            "/admin/addexternal",
            {
                "op": "addexternal",
                "externalname": externalname,
                "type": type,
                "location": location,
                "automount": automount,
                "automounttype": automount_type,
                "automountparam1": automuntparam1,
                "perm": perm,
                "bucket": bucket,
                "region": region,
                "key": key,
                "secret": secret,
                "toplevelprefix": toplevelprefix,
                "enableenc": enableenc,
                "enctype": enctype,
                "kmsid": kmsid,
                "useiamrole": useiamrole,
                "endpoint": endpoint,
                "container": container,
                "accountkey": accountkey,
                "accountname": accountname,
            },
        )

        checkstr = " ".join(resp.itertext()).strip()
        if "Name already exists" in checkstr:
            externals = self.admin_getexternals()

            for ext_item in externals:  # type: ignore
                if ext_item.get("name") == externalname:
                    resp = ext_item

        return resp

    def admin_add_dlp_rule(
        self,
        rule_name: str = "dlp_deny_download",
        str_expression: str = "dlp_deny_download",
        action: str = "DOWNLOAD",
    ) -> None:
        """
        Add dlp deny rule for file name containing expression
        Action: DOWNLOAD, LOGIN, SHARE
        """
        if action == "DOWNLOAD":
            expression = f"(_file.fileNameContains('{str_expression}'))"
        elif action == "LOGIN":
            expression = f"(_user.email == '{str_expression}')"
        else:
            expression = str_expression

        resp = self._api_call(
            "/admin/dlpaddrule",
            {
                "op": "dlpaddrule",
                "rulename": rule_name,
                "type": "DENY",
                "ispermissive": "0",
                "action": action,
                "expression": expression,
                "ruleNotification": "",
            },
        )
        message = resp.findtext("./command/message", "0")
        if message not in ["Rule created successfully", "Rule name already taken"]:
            raise ServerError("", f"Failed to add rule {rule_name}")

    def admin_remove_dlp_rule(self, rule_name: str) -> None:
        """
        Deletes a DLP rule
        """
        resp = self._api_call(
            "/admin/dlpdroprule",
            {
                "op": "dlpdroprule",
                "rulename": rule_name,
            },
        )
        message = resp.findtext("./command/message", "0")
        if message not in ["Rule dropped successfully", "Rule name already dropped"]:
            raise ServerError("", f"Failed to delete rule {rule_name}")

    def admin_set_config_setting(
        self, config_setting_name: str, config_setting_value: str
    ):
        """
        Set a single config setting

        Args:
            config_setting_name (str): TONIDOCLOUD_ string with setting
            config_setting_value (str): value of the config key
        """
        resp = self._api_call(
            "/admin/setconfigsetting",
            {
                "op": "setconfigsetting",
                "count": "1",
                "param0": config_setting_name,
                "value0": config_setting_value,
            },
        )
        self._raise_exception_from_command(resp)

    def admin_clearrmcclients(self, username: str) -> None:
        """
        Remove all RMC Clients found in admin portal associated with a user
        """
        clients = self.admin_getrmcclients(username)

        for client in clients:
            self.admin_removermcclient(client.remote_client_id)

    def admin_waitforrmcclient(
        self, username: str, rmc_count: int, maxwaits: float = 60
    ) -> None:
        """
        Wait for RMC Client count incremente by one in admin portal
        """
        starttime = time.monotonic()

        while time.monotonic() - starttime < maxwaits:
            rmc_clients = self.admin_getrmcclients(username)

            if rmc_clients is not None and len(rmc_clients) >= (rmc_count + 1):
                return

            time.sleep(0.1)

        raise TimeoutError(f"RMC Client count not incremented after {maxwaits} seconds")

    def setuserpassword(self, username: str, new_password: str) -> None:
        """
        Set new password for a user
        """
        resp = self._api_call(
            "/admin/setuserpassword",
            {
                "op": "setuserpassword",
                "profile": username,
                "password": new_password,
                "passwordconfirm": new_password,
            },
        )
        self._raise_exception_from_command(resp)

    def admin_checkshare(
        self, share_owner: str, share_filter: str = "", limit: int = 10
    ) -> None:
        """
        Get shares for specific user/filter if exists.
        Filter can be The share location, share-name or user-name
        """
        resp = self._api_call(
            "/admin/getsharesbyowner",
            {
                "op": "getsharesbyowner",
                "shareowner": share_owner,
                "sharefilter": share_filter,
                "limit": limit,
            },
        )
        meta = resp.find("./meta")
        if meta is None:
            raise ValueError("No shares meta found")

        total_text = meta.findtext("./total")
        if total_text is None:
            raise ValueError("No shares total found")
        total = int(total_text)
        if total != 1:
            raise ValueError(f"Expected 1 share, found {total}")

    def get_share_password(self, share: FCShare) -> str:
        """
        Get share password for a public share.
        """
        resp = self._api_call(
            "/core/getsharepassword",
            {
                "op": "getsharepassword",
                "shareid": share.shareid,
            },
        )
        self._raise_exception_from_command(resp)
        return resp.findtext("./command/message", "")

    def get_permissions_for_group(self, share: FCShare, groupid: str) -> FCShareGroup:
        """
        Returns the permissions for a specific group in the share.
        """
        resp = self._api_call(
            "/core/getgroupaccessforshare",
            {"shareid": share.shareid},
        )

        for entry in resp.findall("./group"):
            if entry.findtext("./groupid") == groupid:
                group = FCShareGroup(
                    groupid=entry.findtext("./groupid", ""),
                    groupname=entry.findtext("./groupname", ""),
                    read=entry.findtext("./read") == "true",
                    write=entry.findtext("./write") == "true",
                    sync=entry.findtext("./sync") == "true",
                    share=entry.findtext("./share") == "true",
                    download=entry.findtext("./download") == "true",
                    disallowdelete=entry.findtext("./disallowdelete") == "true",
                )
                return group

        raise ValueError(f"Group {groupid} not found in share {share.shareid}")

    def getuploadform(self, shareid: str) -> str:
        """
        Get an upload form for a upload-only share - HTML string
        """
        return self._api_call_raw("/core/getuploadform", {"shareid": shareid})

    def get_share_activities(self, share: FCShare) -> list[ShareActivity]:
        """
        Returns activities for a share.
        """
        resp = self._api_call(
            "/core/getshareactivityforshare",
            {"shareid": share.shareid},
        )

        entries: list[ShareActivity] = []

        for entry in resp.findall("./shareactivities"):
            share_id = entry.findtext("./shareid")
            if share_id == share.shareid:
                shares_acts = ShareActivity(
                    shareid=share_id or "",
                    path=entry.findtext("./path") or "",
                    name=entry.findtext("./name") or "",
                    actioncode=int(entry.findtext("./actioncode") or 0),
                    who=entry.findtext("./who") or "",
                    when=entry.findtext("./when") or "",
                    how=entry.findtext("./how") or "",
                    ip=entry.findtext("./ip") or "",
                )
                entries.append(shares_acts)

        return entries
