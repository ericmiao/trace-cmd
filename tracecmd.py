#
# Copyright (C) International Business Machines  Corp., 2009
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# 2009-Dec-17:	Initial version by Darren Hart <dvhltc@us.ibm.com>
#

from functools import update_wrapper
from ctracecmd import *

"""
Python interface to the tracecmd library for parsing ftrace traces

Python tracecmd applications should be written to this interface. It will be
updated as the tracecmd C API changes and try to minimze the impact to python
applications. The ctracecmd Python module is automatically generated using SWIG
and it is recommended applications not use it directly.

TODO: consider a complete class hierarchy of ftrace events...
"""

def cached_property(func, name=None):
    if name is None:
        name = func.__name__
    def _get(self):
        try:
            return self.__cached_properties[name]
        except AttributeError:
            self.__cached_properties = {}
        except KeyError:
            pass
        value = func(self)
        self.__cached_properties[name] = value
        return value
    update_wrapper(_get, func)
    def _del(self):
        self.__cached_properties.pop(name, None)
    return property(_get, None, _del)

class Event(object):
    """
    This class can be used to access event data
    according to an event's record and format.
    """
    __slots__ = ('_pevent', '_record', '_format', 'type', 'cpu', 'ts',
                 'name', '_comm', '_pid')

    def __init__(self, pevent, record, format, type):
        self._pevent = pevent
        self._record = record
        self._format = format
        self.type = type
        self.cpu = pevent_record_cpu_get(record)
        self.ts  = pevent_record_ts_get(record)
        self.name = event_format_name_get(format)
        self._comm = None
        self._pid = None

    def __str__(self):
        return "%d.%d CPU%d %s: pid=%d comm=%s type=%d" % \
               (self.ts/1000000000, self.ts%1000000000, self.cpu, self.name,
                self.num_field("common_pid"), self.comm, self.type)

    def __del__(self):
        free_record(self._record)

    def __getitem__(self, n):
        f = pevent_find_field(self._format, n)
        if f is None:
            raise KeyError("no field '%s'" % n)
        return Field(self._record, f)

    def keys(self):
        return py_format_get_keys(self._format)

    @property
    def comm(self):
        if self._comm is None:
            self._comm = pevent_data_comm_from_pid(self._pevent, self.pid)
        return self._comm

    @property
    def pid(self):
        if self._pid is None:
            self._pid = pevent_data_pid(self._pevent, self._record)
        return self._pid

    def num_field(self, name):
        f = pevent_find_any_field(self._format, name)
        if f is None:
            return None
        ret, val = pevent_read_number_field(f, pevent_record_data_get(self._record))
        if ret:
            return None
        return val

    def str_field(self, name):
        f = pevent_find_any_field(self._format, name)
        if f is None:
            return None
        return py_field_get_str(f, self._record)

class TraceSeq(object):
    def __init__(self, trace_seq):
        self._trace_seq = trace_seq

    def puts(self, s):
        return trace_seq_puts(self._trace_seq, s)

class FieldError(Exception):
    pass

class Field(object):
    def __init__(self, record, field):
        self._record = record
        self._field = field

    @cached_property
    def data(self):
        return py_field_get_data(self._field, self._record)

    def __long__(self):
        ret, val =  pevent_read_number_field(self._field,
                                             pevent_record_data_get(self._record))
        if ret:
            raise FieldError("Not a number field")
        return val
    __int__ = __long__

    def __str__(self):
        return py_field_get_str(self._field, self._record)

class PEvent(object):
    def __init__(self, pevent):
        self._pevent = pevent

    def _handler(self, cb, s, record, event_fmt):
        type = pevent_data_type(self._pevent, record)
        return cb(TraceSeq(s), Event(self._pevent, record, event_fmt, type))

    def register_event_handler(self, subsys, event_name, callback):
        l = lambda s, r, e: self._handler(callback, s, r, e)

        py_pevent_register_event_handler(
                  self._pevent, -1, subsys, event_name, l)

    @cached_property
    def file_endian(self):
        if pevent_is_file_bigendian(self._pevent):
            return '>'
        return '<'


class FileFormatError(Exception):
    pass

class Trace(object):
    """
    Trace object represents the trace file it is created with.

    The Trace object aggregates the tracecmd structures and functions that are
    used to manage the trace and extract events from it.
    """
    def __init__(self, filename):
        self._handle = tracecmd_alloc(filename)

        if tracecmd_read_headers(self._handle):
            raise FileFormatError("Invalid headers")

        if tracecmd_init_data(self._handle):
            raise FileFormatError("Failed to init data")

        self.cpus = tracecmd_cpus(self._handle)
        self._pevent = tracecmd_get_pevent(self._handle)
        self._start_time = None
        self._end_time = None

    @property
    def start_time(self, cpu = -1):
        """
        returns the timestamp of the first event on specified CPU, a default of
        cpu == -1 means the first event on all CPUs, which is kept as the last
        element in the _start_time[] list, as could be referenced by [-1]
        """
        if self._start_time is None:
            self._start_time = []
            for cpu in range(0, self.cpus):
                rec = tracecmd_read_cpu_first(self._handle, cpu)
                self._start_time.append(pevent_record_ts_get(rec) if rec else 0)

            ts = min(filter(lambda v: v > 0, self._start_time))
            self._start_time.append(ts)

        return self._start_time[cpu]

    @property
    def end_time(self, cpu = -1):
        """
        returns the timestamp of the last event on specified CPU, a default of
        cpu == -1 means the last event on all CPUs, which is kept as the last
        element in the _end_time[] list, as could be referenced by [-1]
        """
        if self._end_time is None:
            self._end_time = []
            for cpu in range(0, self.cpus):
                rec = tracecmd_read_cpu_last(self._handle, cpu)
                self._end_time.append(pevent_record_ts_get(rec) if rec else 0)

            ts = max(filter(lambda v: v > 0, self._end_time))
            self._end_time.append(ts)

        return self._end_time[cpu]

    def record_to_event(self, record):
        if record:
            type = pevent_data_type(self._pevent, record)
            format = pevent_data_event_from_type(self._pevent, type)
            if type and format:
                return Event(self._pevent, record, format, type)
        return None

    def read_event(self, cpu):
        rec = tracecmd_read_data(self._handle, cpu)
        return self.record_to_event(rec)

    def read_event_at(self, offset):
        res = tracecmd_read_at(self._handle, offset)
        # SWIG only returns the CPU if the record is None for some reason
        if isinstance(res, int):
            return None
        rec, cpu = res
        return self.record_to_event(rec)

    def peek_event(self, cpu):
        rec = tracecmd_peek_data_ref(self._handle, cpu)
        if rec is None:
            return None
        return self.record_to_event(rec)

    def rewind(self, cpu = -1, start_time = 0):
        if cpu in range(0, self.cpus):
            tracecmd_set_cpu_to_timestamp(self._handle, cpu, start_time)
        else:
            tracecmd_set_all_cpus_to_timestamp(self._handle, start_time)

    def events(self, cpu = -1, start_time = 0, end_time = 0):
        target_cpu = cpu
        for cpu in range(0, self.cpus):
            if target_cpu == cpu or target_cpu == -1:
                self.rewind(cpu, start_time)
                while True:
                    event = self.read_event(cpu)
                    if not event:
                        break
                    if end_time > 0 and event.ts > end_time:
                        break
                    yield event

    def records(self, cpu = -1, start_time = 0, end_time = 0):
        target_cpu = cpu
        for cpu in range(0, self.cpus):
            if target_cpu == cpu or target_cpu == -1:
                self.rewind(cpu, start_time)
                while True:
                    record = tracecmd_read_data(self._handle, cpu)
                    if not record:
                        break
                    ts = pevent_record_ts_get(record)
                    if end_time > 0 and ts > end_time:
                        break
                    yield record

# Basic builtin test, execute module directly
if __name__ == "__main__":
    t = Trace("trace.dat")
    print "Trace contains data for %d cpus" % (t.cpus)

    for cpu in range(0, t.cpus):
        print "CPU %d" % (cpu)
        ev = t.read_event(cpu)
        while ev:
            print "\t%s" % (ev)
            ev = t.read_event(cpu)



