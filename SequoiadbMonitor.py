#!/usr/bin/python
import json
import requests
import hashlib
import argparse
import sys
import time
import signal
import sys

class SdbCoord:
    def __init__(self, sdb_user, sdb_password, sdb_query_timeout, coord_host, tablename):
        self.__sdb_user = sdb_user
        self.__sdb_md5_password = self.__md5_func(sdb_password)
        self.__sdb_query_timeout = sdb_query_timeout
        self.__coord_rest_url = self.__coord_rest_url_func(coord_host)
        self.__tablename = tablename
        self.__headers = None
        self.__tableIsExists = False
        self.___NAME_LIST = ""

    def __coord_rest_url_func(self, coord_host):
        coord_rest_url = 'http://' + coord_host[:-1] + str(4)
        return coord_rest_url

    def __md5_func(self, password):
        hl = hashlib.md5()
        hl.update(password.encode(encoding='utf-8'))
        md5_password = hl.hexdigest()
        return md5_password

    def __login(self):
        if not self.__sdb_user or not self.__sdb_md5_password:
            sdb_user = '""'
            sdb_md5_password = '""'
        else:
            sdb_user = self.__sdb_user
            sdb_md5_password = self.__sdb_md5_password

        command = 'cmd=login&user={}&passwd={}'.format(sdb_user, sdb_md5_password)
        headers = {'Accept': "application/json"}
        try:
            response = requests.request("GET",
                                        self.__coord_rest_url,
                                        data=command,
                                        headers=headers,
                                        timeout=self.__sdb_query_timeout)
            self.__headers = response.headers
            self.__headers['Accept'] = "application/json"
            login_response = json.loads(response.text)
            if len(login_response) > 0:
                status = login_response[0]
                errno = status['errno']
                if errno == 0:
                    _status = 0
                    print('Login success')
                else:
                    _status = -1
                    print('Login failed')
                    print("error no = " + str(errno))
                    print("error description = " + str(status["description"]))
                    print("error detail = " + str(status["detail"]))
        except Exception as ex:
            print("Exception during request to url: {}, payload: {}, error:{}".
                  format(self.__coord_rest_url, command, ex))
        return _status

    def __check_table_exists(self):
        snapshot_list_collections_command = "cmd=exec&sql=" + \
                                            "select push(t2.CataInfo.SubCLName) as Name, t2.IsMainCL as IsMainCL, t2.RealName as RealName " + \
                                            " from " + \
                                            "(" + \
                                            "select t.Name as RealName, t.IsMainCL as IsMainCL, t.CataInfo as CataInfo from $SNAPSHOT_CATA as t where t.Name = '" + self.__tablename + "' split by t.CataInfo" + \
                                            ") as t2"

        command = snapshot_list_collections_command
        if not self.__headers:
            status = self.__login()
            if status != 0:
                return status
        response = requests.request("GET",
                                    self.__coord_rest_url,
                                    data=command,
                                    headers=self.__headers,
                                    timeout=self.__sdb_query_timeout)
        status = -1;
        query_response = json.loads(response.text)
        for record in query_response:
            keys = record.keys()
            if 'errno' in keys:
                continue
            name = record["Name"]
            realName = record["RealName"]
            isMainCl = record["IsMainCL"]
            if realName:
                status = 0
                self.__tableIsExists = True
                break

        if status == -1:
            print("table " + self.__tablename + " is not exists")
            return status, None

        name_list = "("
        if isMainCl:
            for v in name:
                if name_list is "(":
                    name_list += "'" + v + "'"
                else:
                    name_list += "," + "'" + v + "'"
        else:
            name_list += "'" + realName + "'"
        name_list += ")"

        return status, name_list

    def execute(self):
        if not self.__headers:
            status = self.__login()
            if status != 0:
                return status, None
        if not self.__tableIsExists:
            status, name_list = self.__check_table_exists()
            self.__NAME_LIST = name_list


        if self.__tableIsExists:
            snapshot_collections_aggregate_command = "cmd=exec&sql=" + \
                                                     "select t5.Name as Name, " + \
                                                     "sum(t5.TotalRecords) as TotalRecords," + \
                                                     "sum(t5.TotalDataRead) as TotalDataRead," + \
                                                     "sum(t5.TotalIndexRead) as TotalIndexRead," + \
                                                     "sum(t5.TotalDataWrite) as TotalDataWrite," + \
                                                     "sum(t5.TotalIndexWrite) as TotalIndexWrite," + \
                                                     "sum(t5.TotalUpdate) as TotalUpdate," + \
                                                     "sum(t5.TotalDelete) as TotalDelete," + \
                                                     "sum(t5.TotalInsert) as TotalInsert," + \
                                                     "sum(t5.TotalSelect) as TotalSelect," + \
                                                     "sum(t5.TotalRead) as TotalRead," + \
                                                     "sum(t5.TotalWrite) as TotalWrite," + \
                                                     "sum(t5.TotalTbScan) as TotalTbScan," + \
                                                     "sum(t5.TotalIxScan) as TotalIxScan" + \
                                                     " from " + \
                                                     "(" + \
                                                     "select t4.Name as Name, sum(t4.TotalRecords) as TotalRecords," + \
                                                     "sum(t4.TotalDataRead) as TotalDataRead," + \
                                                     "sum(t4.TotalIndexRead) as TotalIndexRead," + \
                                                     "sum(t4.TotalDataWrite) as TotalDataWrite," + \
                                                     "sum(t4.TotalIndexWrite) as TotalIndexWrite," + \
                                                     "sum(t4.TotalUpdate) as TotalUpdate," + \
                                                     "sum(t4.TotalDelete) as TotalDelete," + \
                                                     "sum(t4.TotalInsert) as TotalInsert," + \
                                                     "sum(t4.TotalSelect) as TotalSelect," + \
                                                     "sum(t4.TotalRead) as TotalRead," + \
                                                     "sum(t4.TotalWrite) as TotalWrite," + \
                                                     "sum(t4.TotalTbScan) as TotalTbScan," + \
                                                     "sum(t4.TotalIxScan) as TotalIxScan" + \
                                                     " from " + \
                                                     "(" + \
                                                     "select t3.Name as Name, avg(t3.TotalRecords) as TotalRecords," + \
                                                     "sum(t3.TotalDataRead) as TotalDataRead," + \
                                                     "sum(t3.TotalIndexRead) as TotalIndexRead," + \
                                                     "avg(t3.TotalDataWrite) as TotalDataWrite," + \
                                                     "avg(t3.TotalIndexWrite) as TotalIndexWrite," + \
                                                     "avg(t3.TotalUpdate) as TotalUpdate," + \
                                                     "avg(t3.TotalDelete) as TotalDelete," + \
                                                     "avg(t3.TotalInsert) as TotalInsert," + \
                                                     "sum(t3.TotalSelect) as TotalSelect," + \
                                                     "sum(t3.TotalRead) as TotalRead," + \
                                                     "avg(t3.TotalWrite) as TotalWrite," + \
                                                     "sum(t3.TotalTbScan) as TotalTbScan," + \
                                                     "sum(t3.TotalIxScan) as TotalIxScan" + \
                                                     " from " + \
                                                     "(" + \
                                                     "select t2.Name as Name, t2.Details.GroupName as GroupName," + \
                                                     "t2.Details.TotalRecords as TotalRecords," + \
                                                     "t2.Details.TotalDataRead as TotalDataRead," + \
                                                     "t2.Details.TotalIndexRead as TotalIndexRead," + \
                                                     "t2.Details.TotalDataWrite as TotalDataWrite," + \
                                                     "t2.Details.TotalIndexWrite as TotalIndexWrite," + \
                                                     "t2.Details.TotalUpdate as TotalUpdate," + \
                                                     "t2.Details.TotalDelete as TotalDelete," + \
                                                     "t2.Details.TotalInsert as TotalInsert," + \
                                                     "t2.Details.TotalSelect as TotalSelect," + \
                                                     "t2.Details.TotalRead as TotalRead," + \
                                                     "t2.Details.TotalWrite as TotalWrite," + \
                                                     "t2.Details.TotalTbScan as TotalTbScan," + \
                                                     "t2.Details.TotalIxScan as TotalIxScan" + \
                                                     " from " + \
                                                     "(" + \
                                                     "select t.Name as Name,t.Details as Details from $SNAPSHOT_CL as t where t.Name in " + self.__NAME_LIST + " split by t.Details" + \
                                                     ") as t2" + \
                                                     ") as t3 group by t3.Name, t3.GroupName" + \
                                                     ") as t4 group by t4.Name" + \
                                                     ") as t5"
            command = snapshot_collections_aggregate_command

            response = requests.request("GET",
                                    self.__coord_rest_url,
                                    data=command,
                                    headers=self.__headers,
                                    timeout=self.__sdb_query_timeout)
            query_response = json.loads(response.text)

            if len(query_response) > 0:
                status_details = query_response[0]
                status = -1 if not 'errno' in status_details.keys() else int(status_details['errno'])
                if status != 0:
                    print('Query failed, errno: {}, error: {}, payload: {}'.format(status, status_details, command))
                if status == -179:
                    print(
                        'ATHENTICATION FAILED, errno: {}, error: {}, payload: {}'.format(status, status_details, command))
                    self.__headers = None
        else:
            status = -1
            query_response = None
        return status, query_response

def parse_message(message):
    for record in message:
        keys = record.keys()
        if 'errno' in keys:
            continue

        name         = record["Name"]
        tbScan       = record["TotalTbScan"]
        read         = record["TotalRead"]
        indexRead    = record["TotalIndexRead"]
        insert       = record["TotalInsert"]
        indexWrite   = record["TotalIndexWrite"]
        write        = record["TotalWrite"]
        select       = record["TotalSelect"]
        records      = record["TotalRecords"]
        dataWrite    = record["TotalDataWrite"]
        update       = record["TotalUpdate"]
        dataRead     = record["TotalDataRead"]
        delete       = record["TotalDelete"]
        indexScan    = record["TotalIxScan"]

        if name:
            status = 0
            break
    return name,tbScan,\
           read,indexRead,insert,\
           indexWrite,write,select,\
           records,dataWrite,update,\
           dataRead,delete,indexScan

def quit(signum, frame):
    print "\n"
    print 'You choose to stop me.'
    sys.exit()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SequoiaDB Monitor')
    parser.add_argument('--host', dest='host', action='store', default='localhost:11810', help='coord host')
    parser.add_argument('-u', dest='username', action='store', help='username')
    parser.add_argument('-p', dest='password', action='store', help='password')
    parser.add_argument('-t', dest='table', action='store', required=True, help='table name')
    args = parser.parse_args()

    host = args.host if args.host else "localhost:11810"
    username = args.username if args.username else ""
    password = args.password if args.password else ""
    tablename = args.table if args.table else ""

    try:
        signal.signal(signal.SIGINT, quit)
        signal.signal(signal.SIGTERM, quit)

        # sdb_user, sdb_password, sdb_query_timeout, coord_host
        sdb_coord = SdbCoord(username, password, 30, host, tablename)

        first = True

        strarrs = ['/', '|', '\\', '-']

        begin_time = time.time()
        for i in range(10000):
            status, query_response = sdb_coord.execute()
            if status != 0:
                break
            if first:
                pre_name, pre_tbScan, \
                pre_read, pre_indexRead, pre_insert, \
                pre_indexWrite, pre_write, pre_select, \
                pre_records, pre_dataWrite, pre_update, \
                pre_dataRead, pre_delete, pre_indexScan = parse_message(query_response)
                first = False
            else:
                name, tbScan, \
                read, indexRead, insert, \
                indexWrite, write, select, \
                records, dataWrite, update, \
                dataRead, delete, indexScan = parse_message(query_response)

                over_time = time.time()
                sys.stdout.write(">>> " + strarrs[i % 4] + "\t" +
                                 "Insert:" + str(int((insert - pre_insert) / (over_time - begin_time))) + " , " +
                                 "Read:" + str(int((read - pre_read) / (over_time - begin_time))) + " , " +
                                 "Select:" + str(int((select - pre_select) / (over_time - begin_time))) + " , " +
                                 "IndexRead:" + str(int((indexRead - pre_indexRead) / (over_time - begin_time))) + " , " +
                                 "Update:" + str(int((update - pre_update) / (over_time - begin_time))) + " , " +
                                 "Delete:" + str(int((delete - pre_delete) / (over_time - begin_time))) + " , " +
                                 "IndexWrite:" + str(int((indexWrite - pre_indexWrite) / (over_time - begin_time))) +
                                 " " * 10 +
                                 "\r"
                                 )
                begin_time = over_time
                sys.stdout.flush()
                pre_name, pre_tbScan, \
                pre_read, pre_indexRead, pre_insert, \
                pre_indexWrite, pre_write, pre_select, \
                pre_records, pre_dataWrite, pre_update, \
                pre_dataRead, pre_delete, pre_indexScan = parse_message(query_response)

            time.sleep(1)
    except Exception, exc:
        print exc