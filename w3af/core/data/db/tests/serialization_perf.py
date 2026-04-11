"""
serialization_perf.py

Copyright 2012 Andres Riancho

This file is part of w3af, http://w3af.org/ .

w3af is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation version 2 of the License.

w3af is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with w3af; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

"""

def do_msgpack(obj):
    msg = msgpack.packb([1,2,3])
    msgpack.unpackb(msg)
    
def do_json(obj):
    msg = json.dumps(obj)
    json.loads(msg)

def do_cpickle(obj):
    msg = cPickle.dumps(obj)
    cPickle.loads(msg)

def do_ultrajson(obj):
    msg = ujson.dumps(obj)
    ujson.loads(msg)

def measure(funct, times, *args):
    start = time.time()
    
    for _ in xrange(times):
        funct(*args)
        
    return time.time() - start 

test_objects = [('simple_dict', {'a': 2}),
                ('many_keys_dict', {'a': 1,
                                    'b': 2,
                                    'c': 3,
                                    'd': 4,
                                    'e': 5}),
                ('long_keys_vals', {'a' * 512: 'b' * 512,
                                    'b' * 512: 'c' * 512,}),
                ('very_long_keys_vals', {'a' * 2**16: 'b' * 2**16,
                                         'b' * 2**16: 'c' * 2**16,}),
                ]

tests = [('msgpack', do_msgpack),
         ('json', do_json),
         ('cpickle', do_cpickle),
         ('ujson', do_ultrajson)]

if __name__ == '__main__':
    import time
    import msgpack
    import json
    import cPickle
    import ujson

    for serializator_name, serializator_func in tests:
        total_time = 0
        
        for test_object_name, test_object in test_objects:
            time_spent = measure(serializator_func, 10000, test_object)
            total_time += time_spent
            print('%s took %s seconds to complete %s') % (serializator_name,
                                                         time_spent,
                                                         test_object_name)
            
        print('%s took %s seconds to complete all tests.') % (serializator_name,
                                                             total_time)
        

def run_performance_tests():
    """Run and print performance comparison results."""
    # Note: The actual test results were embedded incorrectly in this file.
    # This is a placeholder for the performance test function.
    pass

if __name__ == '__main__':
    run_performance_tests()
