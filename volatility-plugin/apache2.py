from volatility3.framework import constants, renderers, symbols, interfaces
from volatility3.plugins.linux import pslist
from volatility3.plugins import yarascan

from volatility3.framework.objects import utility

from volatility3.framework.layers import scanners


from volatility3.framework.renderers import format_hints

from volatility3.framework.configuration import requirements

from volatility3.framework.interfaces.layers import TranslationLayerInterface
from volatility3.framework.symbols.linux.extensions import task_struct

from typing import List

import struct
import inspect
import datetime

import yara

class CommonApacheStuff():
    def set_offsets_for_32bit(self):  
        self.pack_format = "I"
        self.bitness = "32bit"
        self.type_size = {
            "char": 1,
            "int":  4,
            "long": 8,
            "pointer":  4,

            "off_t":    8,
            "size_t":   8,
            "apr_size_t": 8,
            "apr_interval_time_t":8,
            "apr_abortfunc_t": 4,
            "apr_port_t":   2,
            "apr_int32_t":  4,
            "apr_socklen_t": 8,     # gleich size_t
            "ap_logconf":   8,
            "apr_off_t":    8,      # gleich wie off_t
            "apr_time_t":   8,
            "apr_int64_t":  8,
            "apr_uint32_t": 4,
        }

        self.initialize_offsets()

    def set_offsets_for_64bit(self):
        self.pack_format = "Q"
        self.bitness = "64bit"
        self.type_size = {
            "char": 1,
            "int":  4,
            "long":     8,
            "pointer":  8,

            "off_t":    8,
            "size_t":   8,
            "apr_size_t": 8,
            "apr_interval_time_t":8,
            "apr_abortfunc_t": 8,
            "apr_port_t":   2,
            "apr_int32_t":  4,
            "apr_socklen_t": 8,     # gleich wie size_t
            "ap_logconf":   16,
            "apr_off_t":    8,      # gleich wie off_t
            "apr_time_t":   8,
            "apr_int64_t":  8,
            "apr_uint32_t": 4,
        }

        self.initialize_offsets()
 
 
 
    ap_conf_vector_t_element_index = {
        "core_server_config_ptr":   0,
        "proxy_server_conf_ptr":    21,
        #27
        "SSLSrvConfigRec_ptr":  28,
        "proxy_conf_dir_ptr": 49,

    }

    _elements_and_types = {
        "proxy_conf_dir": [
            ("p_ptr", "pointer"),
            ("r_ptr", "pointer"),
            ("raliases_ptr", "pointer"),
            ("cookie_paths_ptr", "pointer"),
            ("cookie_domains_ptr", "pointer"),
            ("p_is_fnmatch", "char"),
            ("interpolate_env", "char"),
            ("alias_ptr", "pointer"),
            ("error_override", "int"),
            ("preserve_host", "int"),
            ("preserve_host_set", "int"),
            ("error_override_set", "int"),
            ("alias_set", "int"),
            ("add_forwarded_headers", "int"),
            ("add_forwarded_headers_set", "int"),
            ("refs_ptr", "pointer"),
            ("forward_100_continue", "int"),
            ("forward_100_continue_set", "int"),
            ("error_override_codes_ptr", "pointer"),
            ("async_delay", "apr_interval_time_t"),
            ("async_idle_timeout", "apr_interval_time_t"),
            ("async_delay_set", "int"),
            ("async_idle_timeout_set", "int")
        ],
        "proxy_server_conf": [
            ("proxies_ptr", "pointer"),
            ("sec_proxy_ptr", "pointer"),
            ("aliases_ptr", "pointer"),
            ("noproxies_ptr", "pointer"),
            ("dirconn_ptr", "pointer"),
            ("workers_ptr", "pointer"),
            ("balancers_ptr", "pointer"),
            ("forward_ptr", "pointer"),
            ("reverse_ptr", "pointer"),
            ("domain_ptr", "pointer"),            
            ("id_ptr", "pointer"),                 
            ("pool_ptr", "pointer"),
            ("req", "int"),
            ("max_balancers", "int"),
            ("bgrowth", "int"),
            ("viaopt", "int"),
            ("recv_buffer_size", "apr_size_t"),
            ("io_buffer_size", "apr_size_t"),
            ("maxfwd", "long"),
            ("timeout", "apr_interval_time_t"),
            ("badopt", "int"),
            ("proxy_status", "int"),
            ("source_address_ptr", "pointer"),  
            ("mutex_ptr", "pointer"),         
            ("bslot_ptr", "pointer"),         
            ("storage_ptr", "pointer"),       
            ("req_set", "int"),
            ("viaopt_set", "int"),
            ("recv_buffer_size_set", "int"),
            ("io_buffer_size_set", "int"),
            ("maxfwd_set", "int"),
            ("timeout_set", "int"),
            ("badopt_set", "int"),
            ("proxy_status_set", "int"),
            ("source_address_set", "int"),
            ("bgrowth_set", "int"),
            ("bal_persist", "int"),
            ("inherit", "int"),
            ("inherit_set", "int"),
            ("ppinherit", "int"),
            ("ppinherit_set", "int"),
            ("map_encoded_one", "int"),
            ("map_encoded_all", "int")
        ],
        "apr_pool_t":[
            ("parent_ptr", "pointer"),
            ("child_ptr", "pointer"),
            ("sibling_ptr", "pointer"),
            ("ref_ptr", "pointer"),
            ("cleanups_ptr", "pointer"),
            ("free_cleanups_ptr", "pointer"),
            ("allocator_ptr", "pointer"),
            ("subprocesses_ptr", "pointer"),
            ("abort_fn", "apr_abortfunc_t"),
            ("user_data_ptr", "pointer"),
            ("tag_ptr", "pointer")
        ],
        "apr_sockaddr_t": [
            ("pool_ptr", "pointer"),            # The pool to use...
            ("hostname_ptr", "pointer"),        # The hostname
            ("servname_ptr", "pointer"),        # Either a string of the port number or the service name for the port
            ("port", "apr_port_t"),             # The numeric port
            ("family", "apr_int32_t"),          # The family
            ("salen", "apr_socklen_t"),         # How big is the sockaddr we're using?
            ("ipaddr_len", "int"),              # How big is the ip address structure we're using?
            ("addr_str_len", "int"),            # How big should the address buffer be? 16 for v4 or 46 for v6 used in inet_ntop...
            ("ipaddr_ptr", "pointer")           # This points to the IP address structure within the appropriate sockaddr structure.
        ],
        "server_addr_rec": [
            ("next_ptr", "pointer"),     # The next server in the list
            ("virthost_ptr", "pointer"),  # The name given in "<VirtualHost>"
            ("host_addr_ptr", "pointer"),  # The bound address, for this server
            ("host_port", "apr_port_t")  # The bound port, for this server
        ],
        "process_rec": [
            ("pool_ptr", "pointer"),        # Global pool. Cleared upon normal exit
            ("pconf_ptr", "pointer"),       # Configuration pool. Cleared upon restart
            ("short_name_ptr", "pointer"),      # The program name used to execute the program
            ("argv_ptr", "pointer"),    # The command line arguments
            ("argc", "int")                 # Number of command line arguments passed to the program
        ],
        "server_rec": [
            ("process_ptr", "pointer"),                    # The process this server is running in
            ("next_ptr", "pointer"),                        # The next server in the list
            ("error_fname_ptr", "pointer"),                     # The name of the error log
            ("error_log_ptr", "pointer"),                  # A file descriptor that references the error log
            ("log", "ap_logconf"),                  # The log level configuration
            ("module_config_ptr", "pointer"),              # Config vector containing pointers to modules' per-server config structures
            ("lookup_defaults_ptr", "pointer"),            # MIME type info, etc., before we start checking per-directory info
            ("defn_name_ptr", "pointer"),                 # The path to the config file that the server was defined in
            ("defn_line_number", "int"),              # The line of the config file that the server was defined on
            ("is_virtual", "char"),                        # true if this is the virtual server
            ("port", "apr_port_t"),                        # for redirects, etc.
            ("server_scheme_ptr", "pointer"),             # The server request scheme for redirect responses
            ("server_admin_ptr", "pointer"),                    # The admin's contact information
            ("server_hostname_ptr", "pointer"),                 # The server hostname
            ("addrs_ptr", "pointer"),                      # I haven't got a clue
            ("timeout", "apr_interval_time_t"),            # Timeout, as an apr interval, before we give up
            ("keep_alive_timeout", "apr_interval_time_t"), # The apr interval we will wait for another request
            ("keep_alive_max", "int"),                     # Maximum requests per connection
            ("keep_alive", "int"),                         # Use persistent connections?
            ("names_ptr", "pointer"),                      # Normal names for ServerAlias servers
            ("wild_names_ptr", "pointer"),                 # Wildcarded names for ServerAlias servers
            ("path_ptr", "pointer"),                      # Pathname for ServerPath
            ("pathlen", "int"),                            # Length of path
            ("limit_req_line", "int"),                     # limit on size of the HTTP request line
            ("limit_req_fieldsize", "int"),                # limit on size of any request header field
            ("limit_req_fields", "int"),                   # limit on number of request header fields
            ("context_ptr", "pointer"),                        # Opaque storage location
            ("keep_alive_timeout_set", "int")    # Whether the keepalive timeout is explicit (1) or inherited (0) from the base server
        ],
        # Nochmal anschauen!
        "conn_rec": [
            ("pool_ptr", "pointer"),               # Pool associated with this connection
            ("base_server_ptr", "pointer"),        # Physical vhost this conn came in on
            ("vhost_lookup_data_ptr", "pointer"),      # Used by http_vhost.c
            ("local_addr_ptr", "pointer"),         # Local address
            ("client_addr_ptr", "pointer"),        # Remote address
            ("client_ip_ptr", "pointer"),              # Client's IP address
            ("remote_host_ptr", "pointer"),            # Client's DNS name, if known
            ("remote_logname_ptr", "pointer"),         # Set if doing rfc1413 lookups
            ("local_ip_ptr", "pointer"),               # Server IP address
            ("local_host_ptr", "pointer"),             # Used for ap_get_server_name
            ("id", "long"),                        # ID of this connection
            ("conn_config_ptr", "pointer"),        # Config vector containing pointers to connections per-server config structures
            ("notes_ptr", "pointer"),              # Notes on *this* connection
            ("input_filters_ptr", "pointer"),      # A list of input filters to be used for this connection
            ("output_filters_ptr", "pointer"),     # A list of output filters to be used for this connection
            ("sbh_ptr", "pointer"),                # Handle to scoreboard information for this connection
            ("bucket_alloc_ptr", "pointer"),       # The bucket allocator to use for all bucket/brigade creations
            ("cs_ptr", "pointer"),                 # The current state of this connection
            ("data_in_input_filters", "int"),      # Is there data pending in the input filters?
            ("data_in_output_filters", "int"),     # Is there data pending in the output filters?
            ("clogging_input_filters", "int"),  # Filters that clogg/buffer the input stream
            ("double_reverse", "int"),      # Double-reverse DNS
            ("aborted", "int"),               # Are we still talking?
            ("keepalive", "int"),  # Are we going to keep the connection alive for another request?
            ("keepalives", "int"),                 # How many times have we used it?
            ("log_ptr", "pointer"),                # Optional connection log level configuration
            ("log_id_ptr", "pointer")             # ID to identify this connection in error log
        ],
        "apr_bucket_type_t": [
            ("name_ptr", "pointer"),        # The name of the bucket type
            ("num_func", "int"),            # The number of functions this bucket understands. Can not be less than five.
            ("is_metadata", "int"),           # Whether the bucket contains metadata 
        ],
        "apr_bucket": [
            ("type_ptr", "pointer"),
            ("length", "apr_size_t"),
            ("start", "apr_off_t"),
            ("data_ptr", "pointer"),
            ("free_ptr", "pointer"),
            ("list_ptr", "pointer"),
        ],
        "apr_bucket_heap": [
            ("refcount", "int"),       # Number of buckets using this memory
            ("base_ptr", "pointer"),       # The start of the data actually allocated. This should never be modified, it is only used to free the bucket.
            ("alloc_len", "apr_size_t"),  # how much memory was allocated
        ],
        "apr_bucket_file": [
            ("refcount", "int"),       # Number of buckets using this memory
            ("can_map", "int"),         # Whether this bucket should be memory-mapped if a caller tries to read from it
            ("fd_ptr", "pointer"),       # The file this bucket refers to
            ("readpool_ptr", "pointer"),  # The pool into which any needed structures should be created while reading from this file bucket
            ("read_size", "apr_size_t"),    # File read block size
        ],
        "apr_uri_t": [        
            ("scheme_ptr", "pointer"),
            ("hostinfo_ptr", "pointer"),
            ("user_ptr", "pointer"),
            ("password_ptr", "pointer"),
            ("hostname_ptr", "pointer"),
            ("port_str_ptr", "pointer"),
            ("path_ptr", "pointer"),
            ("query_ptr", "pointer"),
            ("fragment_ptr", "pointer"),
            ("hostent_ptr", "pointer"),
            ("port", "apr_port_t"),
            ("is_initialized", "int"),
            ("dns_looked_up", "int"),
            ("dns_resolved", "int"),
            ("_STRUCT_SIZE", "int"),  # kleiner hack, um die größe rauszufinden
        ],
        "request_rec": [
            ("pool_ptr", "pointer"),             
            ("connection_ptr", "pointer"),       
            ("server_ptr", "pointer"),           
            ("next_ptr", "pointer"),             
            ("prev_ptr", "pointer"),             
            ("main_ptr", "pointer"),             
            ("the_request_ptr", "pointer"),         
            ("assbackwards", "int"),             
            ("proxyreq", "int"),                 
            ("header_only", "int"),              
            ("proto_num", "int"),                
            ("protocol_ptr", "pointer"),             
            ("hostname_ptr", "pointer"),             
            ("request_time", "apr_time_t"),      
            ("status_line_ptr", "pointer"),          
            ("status", "int"),                   
            ("method_number", "int"),            
            ("method_ptr", "pointer"),               
            ("allowed", "apr_int64_t"),          
            ("allowed_xmethods_ptr", "pointer"), 
            ("allowed_methods_ptr", "pointer"),  
            ("sent_bodyct", "apr_off_t"),        
            ("bytes_sent", "apr_off_t"),         
            ("mtime", "apr_time_t"),             
            ("range_ptr", "pointer"),                
            ("clength", "apr_off_t"),            
            ("chunked", "int"),                  
            ("read_body", "int"),                
            ("read_chunked", "int"),             
            ("expecting_100", "int"),   
            ("kept_body_ptr", "pointer"),        
            ("body_table_ptr", "pointer"),       
            ("remaining", "apr_off_t"),         
            ("read_length", "apr_off_t"),        
            ("headers_in_ptr", "pointer"),       
            ("headers_out_ptr", "pointer"),      
            ("err_headers_out_ptr", "pointer"),  
            ("subprocess_env_ptr", "pointer"),   
            ("notes_ptr", "pointer"),            
            ("content_type_ptr", "pointer"),         
            ("handler_ptr", "pointer"),              
            ("content_encoding_ptr", "pointer"),     
            ("content_languages_ptr", "pointer"),
            ("vlist_validator_ptr", "pointer"),      
            ("user_ptr", "pointer"),                 
            ("ap_auth_type_ptr", "pointer"),         
            ("unparsed_uri_ptr", "pointer"),         
            ("uri_ptr", "pointer"),                  
            ("filename_ptr", "pointer"),             
            ("canonical_filename_ptr", "pointer"),   
            ("path_info_ptr", "pointer"),            
            ("args_ptr", "pointer"),                 
            ("used_path_info", "int"),           
            ("eos_sent", "int"),                 
            ("per_dir_config_ptr", "pointer"),   
            ("request_config_ptr", "pointer"),   
            ("log_ptr", "pointer"),              
            ("log_id_ptr", "pointer"),               
            ("htaccess_ptr", "pointer"),         
            ("output_filters_ptr", "pointer"),   
            ("input_filters_ptr", "pointer"),    
            ("proto_output_filters_ptr", "pointer"),
            ("proto_input_filters_ptr", "pointer"),
            ("no_cache", "int"),                 
            ("no_local_copy", "int"),            
            ("invoke_mtx_ptr", "pointer"),       
            #("parsed_uri", "apr_uri_t"),         
            #("finfo", "apr_finfo_t"),            
            #("useragent_addr_ptr", "pointer"),   
            #("useragent_ip", "pointer"),         
            #("trailers_in_ptr", "pointer"),      
            #("trailers_out_ptr", "pointer"),     
            #("useragent_host", "pointer"),       
            #("double_reverse", "int"),           
            #("bnotes", "ap_request_bnotes_t")    
        ],
        "apr_table_entry_t": [
            ("key_ptr", "pointer"),         # The key for the current table entry */
            ("val_ptr", "pointer"),         # The value for the current table entry
            ("key_checksum", "apr_uint32_t")    # A checksum for the key, for use by the apr_table internals
        ],
        "apr_array_header_t": [
            ("pool_ptr", "pointer"),  # The pool the array is allocated out of
            ("elt_size", "int"),      # The amount of memory allocated for each element of the array
            ("nelts", "int"),         # The number of active elements in the array
            ("nalloc", "int"),        # The number of elements allocated in the array
            ("elts_ptr", "pointer")   # The elements in the array
        ],
        "SSLConnRec": [
            ('ssl_ptr', 'pointer'),
            ('client_dn_ptr', 'pointer'),
            ('client_cert_ptr', 'pointer'),
            ('shutdown_type', 'int'),
            ('verify_info_ptr', 'pointer'),
            ('verify_error_ptr', 'pointer'),
            ('verify_depth', 'int'),
            ('disabled', 'int'),
            ('non_ssl_request', 'int'),
            ('reneg_state', 'int'),         # Track the handshake/renegotiation state for the connection
            ('server_ptr', 'pointer'),
            ('dc_ptr', 'pointer'),
            ('cipher_suite_ptr', 'pointer'),    # cipher suite used in last reneg
            ('service_unavailable', 'int'),     # thouugh we negotiate SSL, no requests will be served
            ('vhost_found', 'int')              # whether we found vhost from SNI already 
        ],
        "modssl_ctx_t": [
            ("sc_ptr", "pointer"),  # pointer back to server config
            ("ssl_ctx_ptr", "pointer"),
            ("pks_ptr", "pointer")  # we are one or the other
        ],
        "SSLSrvConfigRec":   [
            ('mc_ptr', 'pointer'),
            ('enabled', 'int'),
            ('vhost_id_ptr', 'pointer'),
            ('vhost_id_len', 'int'),
            ('session_cache_timeout', 'int'),
            ('cipher_server_pref', 'int'),
            ('insecure_reneg', 'int'),
            ('server_ptr', 'pointer')
        ],
        "modssl_pk_server_t": [
            ('cert_files_ptr', 'pointer'),      # Lists of configured certs and keys for this server
            ('key_files_ptr', 'pointer'),
            ('ca_name_path_ptr', 'pointer'),   # Certificates which specify the set of CA names which should be sent in the CertificateRequest message:
            ('ca_name_file_ptr', 'pointer'),
            ('service_unavailable', 'int')      # TLS service for this server is suspended
        ],
        "core_server_config": [
            ('gprof_dir_ptr', 'pointer'),
            ('ap_document_root_ptr', 'pointer'),
            ('access_name_ptr', 'pointer'),
            ('sec_dir_ptr', 'pointer'),
            ('sec_url_ptr', 'pointer'),
            ('redirect_limit', 'int'),
            ('subreq_limit', 'int'),
            ('protocol', 'pointer'),
            ('accf_map_ptr', 'pointer'),
            ('error_log_format_ptr', 'pointer'),
            ('error_log_conn_ptr', 'pointer'),
            ('error_log_req_ptr', 'pointer'),
            ('trace_enable', 'int'),
            ('merge_trailers', 'int'),
            ('protocols_ptr', 'pointer'),
            ('protocols_honor_order', 'int'),
            ('http09_enable', 'char'),
            ('http_conformance', 'char'),
            ('http_methods', 'char'),
            ('merge_slashes', 'int'),
            ('flush_max_threshold', 'apr_size_t'),
            ('flush_max_pipelined', 'apr_int32_t'),
            ('strict_host_check', 'int')
        ],
    }

    # Dicts mit Offset.
    # Werden von initalize_offsets befüllt.
    proxy_conf_dir_offsets = {}
    proxy_server_conf_offsets = {}
    apr_pool_t_offsets = {}
    apr_sockaddr_t_offsets = {}
    server_addr_rec_offsets = {}
    process_rec_offsets = {}
    server_rec_offsets = {}
    conn_rec_offsets = {}
    apr_bucket_type_t_offsets = {}
    apr_bucket_offsets = {}
    apr_bucket_heap_offsets = {}
    apr_bucket_file_offsets = {}
    request_rec_offsets = {}
    apr_uri_t_offsets = {}
    apr_table_entry_t_offsets = {}
    apr_array_header_t_offsets = {}
    SSLConnRec_offsets = {}
    modssl_ctx_t_offsets = {}
    SSLSrvConfigRec_offsets = {}
    modssl_pk_server_t_offsets = {}
    core_server_config_offsets = {}

    def initialize_offsets(self):
        self.initialize_given_offset(self.proxy_conf_dir_offsets, self._elements_and_types["proxy_conf_dir"])

        self.initialize_given_offset(self.proxy_server_conf_offsets, self._elements_and_types["proxy_server_conf"])

        self.initialize_given_offset(self.apr_pool_t_offsets, self._elements_and_types["apr_pool_t"])

        self.initialize_given_offset(self.apr_sockaddr_t_offsets, self._elements_and_types["apr_sockaddr_t"])

        self.initialize_given_offset(self.server_addr_rec_offsets, self._elements_and_types["server_addr_rec"])

        self.initialize_given_offset(self.process_rec_offsets, self._elements_and_types["process_rec"])

        self.initialize_given_offset(self.server_rec_offsets, self._elements_and_types["server_rec"])
        
        self.initialize_given_offset(self.conn_rec_offsets, self._elements_and_types["conn_rec"])
        # nochmal anschaun
        
        self.initialize_given_offset(self.apr_bucket_type_t_offsets, self._elements_and_types["apr_bucket_type_t"])

        self.initialize_given_offset(self.apr_bucket_offsets, self._elements_and_types["apr_bucket"])
        
        
        self.initialize_given_offset(self.apr_bucket_heap_offsets, self._elements_and_types["apr_bucket_heap"])
        
        
        self.initialize_given_offset(self.apr_bucket_file_offsets, self._elements_and_types["apr_bucket_file"])
        # alte version falsch, wird eh nicht genutzt
        
        self.initialize_given_offset(self.request_rec_offsets, self._elements_and_types["request_rec"])
        
        self.initialize_given_offset(self.apr_table_entry_t_offsets, self._elements_and_types["apr_table_entry_t"])
    
        self.initialize_given_offset(self.apr_array_header_t_offsets, self._elements_and_types["apr_array_header_t"])
       
        self.initialize_given_offset(self.SSLConnRec_offsets, self._elements_and_types["SSLConnRec"])
        
        self.initialize_given_offset(self.modssl_ctx_t_offsets, self._elements_and_types["modssl_ctx_t"])
            
        self.initialize_given_offset(self.SSLSrvConfigRec_offsets, self._elements_and_types["SSLSrvConfigRec"])
        # alt unvollständig
        
        self.initialize_given_offset(self.modssl_pk_server_t_offsets, self._elements_and_types["modssl_pk_server_t"])
        
        self.initialize_given_offset(self.core_server_config_offsets, self._elements_and_types["core_server_config"])
        # alt unvollständig
        
    def initialize_given_offset(self, offsets, names_and_types):
        counter = [0]
        for name, type in names_and_types:
            offsets[name] = self.next_multiple_of_n(counter, self.type_size[type])
    
    def next_multiple_of_n(self, offset, size):
        if self.bitness == "64bit":
            biggest_natural_datatype = 8
        else:
            biggest_natural_datatype = 4

        allign_at_multiple = min(size, biggest_natural_datatype)
        next_multiple = (offset[0] + allign_at_multiple - 1) // allign_at_multiple * allign_at_multiple
        offset[0] = next_multiple + size
        return next_multiple
    



    def parse_string(self, proc_layer:TranslationLayerInterface, string_addr:int) -> str:
        """
        Ließt String an adresse 'string_addr'.
        Params: string_addr -> Adresse, an der der String vermutet wird.
        Returns:   Den decodierten String, falls erfolgreich decodierbar.
                "[-] string n/a", sonst.
        """
        string_bytes = b''
        offset = 0
        try:
            while True:
                char = proc_layer.read(string_addr + offset, 1)
                if(char == b'\x00'):
                    break
                string_bytes += char
                offset += 1

            try:
                return string_bytes.decode("utf-8")
            except:
                return "String kein utf-8."
        except Exception as e: 
            #print(e)
            return ""
    

    def read_n_bytes(self, proc_layer:TranslationLayerInterface, addr, n) -> int:
        try:
            return int.from_bytes(proc_layer.read(addr, n), 'little')
        except:
            return

    def read_char(self, proc_layer: TranslationLayerInterface, addr) -> int:
        """
        Liest char an Adresse "addr" und gibt diesen als Integer zurück.

        Args:
            proc_layer (TranslationLayerInterface): Der process layer.
            addr (int): Die Adresse.

        Returns:
            int: Der extrahierte char als Integer als Integer.
        """
        return self.read_n_bytes(proc_layer, addr, self.type_size["char"])

    def read_int(self, proc_layer: TranslationLayerInterface, addr) -> int:
        """
        Liest int an Adresse "addr" und gibt diesen als Integer zurück.

        Args:
            proc_layer (TranslationLayerInterface): Der process layer.
            addr (int): Die Adresse.

        Returns:
            int: Der extrahierte Integer als Integer.
        """
        return self.read_n_bytes(proc_layer, addr, self.type_size["int"])

    def read_long(self, proc_layer: TranslationLayerInterface, addr) -> int:
        """
        Liest long an Adresse "addr" und gibt diesen als Integer zurück.

        Args:
            proc_layer (TranslationLayerInterface): Der process layer.
            addr (int): Die Adresse.

        Returns:
            int: Der extrahierte long Integer als Integer.
        """
        return self.read_n_bytes(proc_layer, addr, self.type_size["long"])

    def read_pointer(self, proc_layer: TranslationLayerInterface, addr) -> int:
        """
        Liest pointer an Adresse "addr" und gibt diesen als Integer zurück.

        Args:
            proc_layer (TranslationLayerInterface): Der process layer.
            addr (int): Die Adresse.

        Returns:
            int: Der extrahierte Pointer Wert als Integer.
        """
        return self.read_n_bytes(proc_layer, addr, self.type_size["pointer"])

    def read_off_t(self, proc_layer: TranslationLayerInterface, addr) -> int:
        """
        Liest off_t an Adresse "addr" und gibt diesen als Integer zurück.

        Args:
            proc_layer (TranslationLayerInterface): Der process layer.
            addr (int): Die Adresse.

        Returns:
            int: Der extrahierte off_t Wert als Integer.
        """
        return self.read_n_bytes(proc_layer, addr, self.type_size["off_t"])

    def read_size_t(self, proc_layer: TranslationLayerInterface, addr) -> int:
        """
        Liest size_t an Adresse "addr" und gibt diesen als Integer zurück.

        Args:
            proc_layer (TranslationLayerInterface): Der process layer.
            addr (int): Die Adresse.

        Returns:
            int: Der extrahierte size_t Wert als Integer.
        """
        return self.read_n_bytes(proc_layer, addr, self.type_size["size_t"])

    def read_apr_size_t(self, proc_layer: TranslationLayerInterface, addr) -> int:
        """
        Liest apr_size_t an Adresse "addr" und gibt diesen als Integer zurück.

        Args:
            proc_layer (TranslationLayerInterface): Der process layer.
            addr (int): Die Adresse.

        Returns:
            int: Der extrahierte apr_size_t Wert als Integer.
        """
        return self.read_n_bytes(proc_layer, addr, self.type_size["apr_size_t"])

    def read_apr_interval_time_t(self, proc_layer: TranslationLayerInterface, addr) -> int:
        """
        Liest apr_interval_time_t an Adresse "addr" und gibt diesen als Integer zurück.

        Args:
            proc_layer (TranslationLayerInterface): Der process layer.
            addr (int): Die Adresse.

        Returns:
            int: Der extrahierte apr_interval_time_t Wert als Integer.
        """
        return self.read_n_bytes(proc_layer, addr, self.type_size["apr_interval_time_t"])

    def read_apr_abortfunc_t(self, proc_layer: TranslationLayerInterface, addr) -> int:
        """
        Liest apr_abortfunc_t an Adresse "addr" und gibt diesen als Integer zurück.

        Args:
            proc_layer (TranslationLayerInterface): Der process layer.
            addr (int): Die Adresse.

        Returns:
            int: Der extrahierte apr_abortfunc_t Wert als Integer.
        """
        return self.read_n_bytes(proc_layer, addr, self.type_size["apr_abortfunc_t"])

    def read_apr_port_t(self, proc_layer: TranslationLayerInterface, addr) -> int:
        """
        Liest apr_port_t an Adresse "addr" und gibt diesen als Integer zurück.

        Args:
            proc_layer (TranslationLayerInterface): Der process layer.
            addr (int): Die Adresse.

        Returns:
            int: Der extrahierte apr_port_t Wert als Integer.
        """
        return self.read_n_bytes(proc_layer, addr, self.type_size["apr_port_t"])

    def read_apr_int32_t(self, proc_layer: TranslationLayerInterface, addr) -> int:
        """
        Liest apr_int32_t an Adresse "addr" und gibt diesen als Integer zurück.

        Args:
            proc_layer (TranslationLayerInterface): Der process layer.
            addr (int): Die Adresse.

        Returns:
            int: Der extrahierte apr_int32_t Wert als Integer.
        """
        return self.read_n_bytes(proc_layer, addr, self.type_size["apr_int32_t"])

    def read_apr_socklen_t(self, proc_layer: TranslationLayerInterface, addr) -> int:
        """
        Liest apr_socklen_t an Adresse "addr" und gibt diesen als Integer zurück.

        Args:
            proc_layer (TranslationLayerInterface): Der process layer.
            addr (int): Die Adresse.

        Returns:
            int: Der extrahierte apr_socklen_t Wert als Integer.
        """
        return self.read_n_bytes(proc_layer, addr, self.type_size["apr_socklen_t"])

    def read_ap_logconf(self, proc_layer: TranslationLayerInterface, addr) -> int:
        """
        Liest ap_logconf an Adresse "addr" und gibt diesen als Integer zurück.

        Args:
            proc_layer (TranslationLayerInterface): Der process layer.
            addr (int): Die Adresse.

        Returns:
            int: Der extrahierte ap_logconf Wert als Integer.
        """
        return self.read_n_bytes(proc_layer, addr, self.type_size["ap_logconf"])

    def read_apr_off_t(self, proc_layer: TranslationLayerInterface, addr) -> int:
        """
        Liest apr_off_t an Adresse "addr" und gibt diesen als Integer zurück.

        Args:
            proc_layer (TranslationLayerInterface): Der process layer.
            addr (int): Die Adresse.

        Returns:
            int: Der extrahierte apr_off_t Wert als Integer.
        """
        return self.read_n_bytes(proc_layer, addr, self.type_size["apr_off_t"])

    def read_apr_time_t(self, proc_layer: TranslationLayerInterface, addr) -> int:
        """
        Liest apr_time_t an Adresse "addr" und gibt diesen als Integer zurück.

        Args:
            proc_layer (TranslationLayerInterface): Der process layer.
            addr (int): Die Adresse.

        Returns:
            int: Der extrahierte apr_time_t Wert als Integer.
        """
        return self.read_n_bytes(proc_layer, addr, self.type_size["apr_time_t"])

    def read_apr_int64_t(self, proc_layer: TranslationLayerInterface, addr) -> int:
        """
        Liest apr_int64_t an Adresse "addr" und gibt diesen als Integer zurück.

        Args:
            proc_layer (TranslationLayerInterface): Der process layer.
            addr (int): Die Adresse.

        Returns:
            int: Der extrahierte apr_int64_t Wert als Integer.
        """
        return self.read_n_bytes(proc_layer, addr, self.type_size["apr_int64_t"])

    def read_apr_uint32_t(self, proc_layer: TranslationLayerInterface, addr) -> int:
        """
        Liest apr_uint32_t an Adresse "addr" und gibt diesen als Integer zurück.

        Args:
            proc_layer (TranslationLayerInterface): Der process layer.
            addr (int): Die Adresse.

        Returns:
            int: Der extrahierte apr_uint32_t Wert als Integer.
        """
        return self.read_n_bytes(proc_layer, addr, self.type_size["apr_uint32_t"])




    def get_pointer_and_read_string(self, proc_layer:TranslationLayerInterface, pointer_addr) -> str:
        """
        Liest pointer an adresse pointer_addr, und gibt den String zurück, welcher an der Adresse des gelesenen Pointers steht.
        Params:   pointer_addr -> Adresse des pointers.
        Returns:  Gelesener String, bei Erfolg.
                Null, bei exception.
        """
        try:
            ptr = int.from_bytes(proc_layer.read(pointer_addr, self.type_size["pointer"]), 'little')
            return self.parse_string(proc_layer, ptr)
        except:
            return
        

    def parse_apr_table_entry_t(self, proc_layer:TranslationLayerInterface, apr_table_entry_t_addr:int, apr_table_entry_t_size:int):
        if not apr_table_entry_t_addr or apr_table_entry_t_addr == 0:
            return
        
        key = self.get_pointer_and_read_string(proc_layer, apr_table_entry_t_addr + self.apr_table_entry_t_offsets["key_ptr"])
        val = self.get_pointer_and_read_string(proc_layer, apr_table_entry_t_addr + self.apr_table_entry_t_offsets["val_ptr"])
        #print("key:", key, ", val:", val)
        if val and key:
            return key + ":"+ val
        
        if key:
            return key
        
        return val
        
    def parse_apr_array_header_t(self, proc_layer:TranslationLayerInterface, apr_array_header_t_addr:str):
        if not apr_array_header_t_addr:
            return
 
        #print("apr_array_header_t_addr", apr_array_header_t_addr)
        # In manchen Fällen existiert eine Adresse auf ein apr_array_header_t, allerding scheint an dieser kein Speicherplatz allokiert zu sein.
        # In diesem Fall wird ein Fehler geworfen
        try:
            proc_layer.read(apr_array_header_t_addr, 1)
        except:
            return
        
        pool_ptr = self.read_pointer(proc_layer, apr_array_header_t_addr + self.apr_array_header_t_offsets["pool_ptr"])
        tag = self.get_pointer_and_read_string(proc_layer, pool_ptr + self.apr_pool_t_offsets["tag_ptr"])
        #print("tag", tag)

        if not tag:
            return

        elt_size = self.read_int(proc_layer, apr_array_header_t_addr + self.apr_array_header_t_offsets["elt_size"])
        #print(f"         elt_size:  ", elt_size)
        nelts = self.read_int(proc_layer, apr_array_header_t_addr + self.apr_array_header_t_offsets["nelts"])
        #print(f"         nelts:     ", nelts)
        nalloc = self.read_int(proc_layer, apr_array_header_t_addr + self.apr_array_header_t_offsets["nalloc"])
        #print(f"         nalloc:    ", nalloc)
        elts_ptr = self.read_pointer(proc_layer, apr_array_header_t_addr + self.apr_array_header_t_offsets["elts_ptr"])
        #print("          elts_ptr", elts_ptr)


        if not elts_ptr or elts_ptr == 0:
            return
        
        if elt_size == 0:
            return
        
        if elt_size * nelts > 8000:
            return
        
        # Wenn nelts gesetzt ist geh ließ netlts Elemente
        headers = ""
        if nelts:
            for n in range(0, nelts):
                header = self.parse_apr_table_entry_t(proc_layer, elts_ptr + n*elt_size ,elt_size)
                headers += header
                if n < nelts - 1:
                    headers += ", "
        """
        else:
            for n in range(0, nalloc):
                header = self.parse_apr_table_entry_t(proc_layer, elts_ptr + n*elt_size ,elt_size)
                if not header or "[-] string n/a" in header:
                    continue
                #print("header", header)
                headers += header
                if n < nalloc - 1:
                    headers += ", "

        #print("headers", headers)"""
        return headers
    
    def parse_proxy_alias(self, proc_layer, proxy_alias_addr):
        #print(f"proxy_alias_addr {proxy_alias_addr:#0x}")
        real = self.get_pointer_and_read_string(proc_layer, proxy_alias_addr + 0)
        fake = self.get_pointer_and_read_string(proc_layer, proxy_alias_addr + self.type_size["pointer"])
        #print("real", real)
        #print("fake", fake)
        return (real, fake)


    def parse_apr_array_header_t_aliases(self, proc_layer:TranslationLayerInterface, apr_array_header_t_addr:str):
        if not apr_array_header_t_addr:
            return
 
        #print("apr_array_header_t_addr", apr_array_header_t_addr)
        # In manchen Fällen existiert eine Adresse auf ein apr_array_header_t, allerding scheint an dieser kein Speicherplatz allokiert zu sein.
        # In diesem Fall wird ein Fehler geworfen
        try:
            proc_layer.read(apr_array_header_t_addr, 1)
        except:
            return
        
        pool_ptr = self.read_pointer(proc_layer, apr_array_header_t_addr + self.apr_array_header_t_offsets["pool_ptr"])
        tag = self.get_pointer_and_read_string(proc_layer, pool_ptr + self.apr_pool_t_offsets["tag_ptr"])
        #print("tag", tag)

        if not tag:
            return

        elt_size = self.read_int(proc_layer, apr_array_header_t_addr + self.apr_array_header_t_offsets["elt_size"])
        #print(f"         elt_size:  ", elt_size)
        nelts = self.read_int(proc_layer, apr_array_header_t_addr + self.apr_array_header_t_offsets["nelts"])
        #print(f"\n         nelts:     ", nelts)
        nalloc = self.read_int(proc_layer, apr_array_header_t_addr + self.apr_array_header_t_offsets["nalloc"])
        #print(f"\n         nalloc:    ", nalloc)
        elts_ptr = self.read_pointer(proc_layer, apr_array_header_t_addr + self.apr_array_header_t_offsets["elts_ptr"])
        #print("          elts_ptr", elts_ptr)


        if not elts_ptr or elts_ptr == 0:
            return
        
        if elt_size == 0:
            return
        
        if elt_size * nelts > 8000:
            return
        
        aliases = []
        for i in range(0, nelts):
            #print("laufe")
            alias_ptr = elts_ptr + i*40
            alias = self.parse_proxy_alias(proc_layer, alias_ptr)
            aliases.append(alias)
        
        
        return aliases
    
    def format_output(self, output:List) -> List:
        for i in range(0, len(output)):
            if output[i] is None:
                output[i] = "-"
            elif type(output[i]) == str:
                if output[i] == "":
                    output[i] = "-"
            elif type(output[i]) == int:
                output[i] = str(output[i])
        
        return output
        




class Configuration(interfaces.plugins.PluginInterface, CommonApacheStuff):
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            # Specifies the OS for which the ülugin was built
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            # Specifies the dependency for the pslist-plugin
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
        ]
    
    def is_process_rec_valid(self, proc_layer:TranslationLayerInterface, process_rec_addr:int) -> bool:
        """
        Validiert potenzielle process_rec Adressen.
        Params:   process_rec_addr -> potenzielle Startadresse für ein process_rec.
        Returns:  True, wenn es sich wahrscheinlich um ein process_rec handelt.
                False, sonst.
        """
        try:
            if not process_rec_addr:
                return False

            #print("process_rec_addr", process_rec_addr)
            # Bei einem validen process_rec darf der pool Pointer nicht 0 sein.
            pool_ptr = self.read_pointer(proc_layer, process_rec_addr)
            if pool_ptr == 0:
                return False

            # Bei einem validen process_rec darf der short_name Pointer nicht 0 sein.
            short_name_ptr = self.read_pointer(proc_layer, process_rec_addr + self.process_rec_offsets["short_name_ptr"])
            if short_name_ptr == 0:
                return False
            
            
            # Zudem sollte der short_name Pointer auf den String "apache2" zeigen.
            short_name = self.parse_string(proc_layer, short_name_ptr)
            if short_name not in ("apache2", "httpd"):
                return False
            
            return True
        except Exception as e: 
            print("Fehler in is_process_rec_valid:", e)
            return False

    def is_apr_sockaddr_t_valid(self, proc_layer:TranslationLayerInterface, apr_sockaddr_t_addr:int) -> bool:
        """
        Validiert potenzielle apr_sockaddr_t Adressen.
        Params:   apr_sockaddr_t_addr -> potenzielle Startadresse für ein apr_sockaddr_t.
        Returns:  True, wenn es sich wahrscheinlich um ein apr_sockaddr_t handelt.
                False, sonst.
        """
        try:

            hostname = self.get_pointer_and_read_string(proc_layer, apr_sockaddr_t_addr + self.apr_sockaddr_t_offsets["hostname_ptr"])
            #print("hostname", hostname)
            # Wenn Port außerhalb der gültigen Range dann ungültig
            port = self.read_n_bytes(proc_layer, apr_sockaddr_t_addr + self.apr_sockaddr_t_offsets["port"], 2)
            #print("port", port)
            if port is None:
                return False
            
            if port > 65535 or port < 0:
                return False
            
            # Wahrscheinlich von hier: https://docs.freebsd.org/en/books/developers-handbook/sockets/
            family = self.read_n_bytes(proc_layer, apr_sockaddr_t_addr + self.apr_sockaddr_t_offsets["family"], 4)
            if family is None:
                return False
            #print("family", family)
            if family > 37 or family <= 0:
                return False
            
            ipaddr_len  = self.read_int(proc_layer, apr_sockaddr_t_addr + self.apr_sockaddr_t_offsets["ipaddr_len"])
            #print("ipaddr_len", ipaddr_len)
            if not ipaddr_len:
                return False
            if ipaddr_len not in [16, 46]:
                return False
            """
            addr_str_len = self.read_int(proc_layer, apr_sockaddr_t_addr + self.apr_sockaddr_t_offsets["addr_str_len"])
            print("addr_str_len", addr_str_len)
            if not addr_str_len:
                return False
            if addr_str_len not in [16, 46]:
                return False
            """

            return True
        except Exception as e: 
            print("Fehler in is_apr_sockaddr_t_valid:", e)
            return False

    def is_server_addr_rec_valid(self, proc_layer:TranslationLayerInterface, server_addr_rec_addr:int) -> bool:
        """
        Validiert potenzielle server_addr_rec Adressen.
        Params:   server_addr_rec -> potenzielle Startadresse für ein server_addr_rec.
        Returns:  True, wenn es sich wahrscheinlich um ein server_addr_rec handelt.
                False, sonst.
        """
        try:
            virthost = self.get_pointer_and_read_string(proc_layer, server_addr_rec_addr + self.server_addr_rec_offsets["virthost_ptr"])
            #print("virthost", virthost)

            host_addr_ptr = self.read_pointer(proc_layer, server_addr_rec_addr + self.server_addr_rec_offsets["host_addr_ptr"])
            if not host_addr_ptr:
                return False
            #print("host_addr_ptr", host_addr_ptr)
            if not self.is_apr_sockaddr_t_valid(proc_layer, host_addr_ptr):
                return False

            host_port = self.read_n_bytes(proc_layer, server_addr_rec_addr + self.server_addr_rec_offsets["host_port"], 2)
            #print("host_port", host_port)

            return True
        except Exception as e: 
            print("Fehler in is_server_addr_rec_valid:", e)
            return False
 
    def is_server_rec_valid(self, proc_layer:TranslationLayerInterface, server_rec_addr:int) -> bool:
        """
        Validiert potenzielle server_rec Adressen.
        Params:   server_rec_addr -> potenzielle Startadresse für ein server_rec.
        Returns:  True, wenn es sich wahrscheinlich um ein server_rec handelt.
                  False, sonst.
        """
        try:
            error_fname = self.get_pointer_and_read_string(proc_layer, server_rec_addr + self.server_rec_offsets["error_fname_ptr"])
            #print("error_fname:         ", error_fname)

            server_hostname = self.get_pointer_and_read_string(proc_layer, server_rec_addr + self.server_rec_offsets["server_hostname_ptr"])
            #print("server_hostname:         ", server_hostname)

            defn_line_number = self.read_int(proc_layer, server_rec_addr + self.server_rec_offsets["defn_line_number"])
            #print("defn_line_number", defn_line_number)

            # Wenn is_virtual true (1) ist, dann handelt es sich um virtuellen server. Bei false (0) nicht -> apache doku
            is_virtual = int.from_bytes(proc_layer.read(server_rec_addr + self.server_rec_offsets["is_virtual"], 1), 'little')
            if is_virtual not in [0, 1]:
                return False
            
            # Prüft, ob die server_addr_rec Struktur valide ist.
            addrs_ptr = self.read_pointer(proc_layer, server_rec_addr + self.server_rec_offsets["addrs_ptr"])
            #print("addrs_ptr", addrs_ptr)
            if not self.is_server_addr_rec_valid(proc_layer, addrs_ptr):
                return False
            
            path = self.get_pointer_and_read_string(proc_layer, server_rec_addr + self.server_rec_offsets["path_ptr"])
            #print("path", path)

            port = self.read_n_bytes(proc_layer, server_rec_addr + self.server_rec_offsets["port"], 2)
            #print("port", port)
            # keep_alive_timeout_set ist laut Dokumentation entweder 0 oder 1
            keep_alive_timeout_set = self.read_int(proc_layer, server_rec_addr + self.server_rec_offsets["keep_alive_timeout_set"])
            #print("keep_alive_timeout_set", keep_alive_timeout_set)
            if keep_alive_timeout_set not in [0, 1]:
                return False

            #server_hostname = self.get_pointer_and_read_string(proc_layer, server_rec_addr + server_rec_offsets["server_hostname_ptr"])
            return True   
        except Exception as e: 
            print("Fehler in is_server_rec_valid:", e)
            return False



    def get_core_server_config_addr(self, proc_layer:TranslationLayerInterface, ap_conf_vector_t_addr:int):
        core_server_config_ptr = self.read_pointer(proc_layer, ap_conf_vector_t_addr + self.type_size["pointer"] * self.ap_conf_vector_t_element_index["core_server_config_ptr"])

        return core_server_config_ptr
    
    def get_apr_pool_t_addrs(self, proc_layer:TranslationLayerInterface, task:task_struct) -> List:
        """
        Findet mögliche Startadressen von apr_pool_t Strukten.
        Returns:  Null, falls keine gefunden wurden.
                Liste der möglichen Startadressen der apr_pool_t Strukturen, sonst.
        """
        # pconf_addrs enthält die Adressen, an denen der String 'pconf' gefunden wurde
        pconf_addrs = []
        for address in proc_layer.scan(
            self.context,
            scanners.BytesScanner(b"pconf"),
            sections=task.get_process_memory_sections(),
        ):
            pconf_addrs.append(address)
        
        
        #print("pconf_addrs", pconf_addrs)
        if pconf_addrs == []:
            return
        
        # pconf_pointer_addrs enthält die gefundenen Adressen der Pointer, welche auf die pconf Strings zeigen
        pconf_pointer_addrs = []
        for pconf_addr in pconf_addrs:
            for addr in proc_layer.scan(
                self.context,
                scanners.BytesScanner(struct.pack(self.pack_format, pconf_addr)),
                sections=task.get_process_memory_sections(),
            ):
                pconf_pointer_addrs.append(addr)

        #print("pconf_pointer_addrs", pconf_pointer_addrs)
        if pconf_pointer_addrs == []:
            return

        # apr_pool_t_addrs enthält die Startadressen von den vermuteten apr_pool_t_addrs Structs.
        apr_pool_t_addrs = []
        for pconf_pointer_addr in pconf_pointer_addrs:
            apr_pool_t_addrs.append(pconf_pointer_addr - self.apr_pool_t_offsets["tag_ptr"])

        return apr_pool_t_addrs

    def get_process_rec_addrs(self, proc_layer:TranslationLayerInterface, task:task_struct, apr_pool_t_addrs:List) -> List:
        """
        Findet mögliche Startadresse von process_rec Strukturen.
        Params:   apr_pool_t_addrs: Gefundene mögliche Startadressen von apr_pool_t Strukten.
        Returns:  Null, falls keine gefunden wurden.
                Liste der möglichen Startadressen der process_rec Strukturen, sonst.
        """
        # apr_pool_t_addrs enthält die Adressen, an denen ein Pointer auf die vermuteten apr_pool_t Strukturen gefunden wurden
        apr_pool_t_ptr_addrs = []
        for apr_pool_t_addr in apr_pool_t_addrs:
            for addr in proc_layer.scan(
                self.context,
                scanners.BytesScanner(struct.pack(self.pack_format, apr_pool_t_addr)),
                sections=task.get_process_memory_sections(),
            ):
                apr_pool_t_ptr_addrs.append(addr)
        
        if apr_pool_t_ptr_addrs == []:
            return

        # potential_process_rec_addrs enthält die potenziellen Startadressen der process_rec Strukturen.
        potential_process_rec_addrs = []
        for apr_pool_t_ptr_addr in apr_pool_t_ptr_addrs:
            potential_process_rec_addrs.append(apr_pool_t_ptr_addr - self.process_rec_offsets["pconf_ptr"])
        
        # process_rec_addrs enthält die nach einer validierung übrig gebliebenen Startadressen auf die process_rec Strukturen
        process_rec_addrs = []
        for potential_process_rec_addr in potential_process_rec_addrs:
            if(self.is_process_rec_valid(proc_layer, potential_process_rec_addr)):
                process_rec_addrs.append(potential_process_rec_addr)

        if process_rec_addrs == []:
            return

        return process_rec_addrs
        
    def get_server_rec_addrs(self, proc_layer:TranslationLayerInterface, task:task_struct, process_rec_addrs:List) -> List:
        """ 
        Findet mögliche Startadresse von server_rec Strukturen.
        Params:   process_rec_addrs: Gefundene mögliche Startadressen von process_rec Strukten.
        Returns:  Null, falls keine gefunden wurden.
                Liste der möglichen Startadressen der server_rec Strukturen, sonst.
        """
        # process_rec_ptr_addrs enthält die Adressen, an denen ein Pointer auf die vermuteten process_rec Strukturen gefunden wurden
        process_rec_ptr_addrs = []
        for process_rec_addr in process_rec_addrs:
            for addr in proc_layer.scan(
                self.context,
                scanners.BytesScanner(struct.pack(self.pack_format, process_rec_addr)),
                sections=task.get_process_memory_sections(),
            ):
                process_rec_ptr_addrs.append(addr)
        
        if process_rec_ptr_addrs == []:
            return

        # potential_server_rec_addrs enthält die potenziellen Startadressen der server_rec Strukturen.
        # Der Pointer auf die porcess_rec Strukturen befindet sich am Anfang der server_rec Struktur.
        potential_server_rec_addrs = process_rec_ptr_addrs
        #print("potential_server_rec_addrs", potential_server_rec_addrs)
        # server_rec_addrs enthält die nach einer validierung übrig gebliebenen Startadressen auf die server_rec Strukturen
        server_rec_addrs = []
        for potential_server_rec_addr in potential_server_rec_addrs:
            if(self.is_server_rec_valid(proc_layer, potential_server_rec_addr)):
                server_rec_addrs.append(potential_server_rec_addr)
        
        if server_rec_addrs == []:
            return 
        
        return server_rec_addrs



    def parse_core_server_config(self, proc_layer:TranslationLayerInterface, core_server_config_addr:int):
        ap_document_root = self.get_pointer_and_read_string(proc_layer, core_server_config_addr + self.core_server_config_offsets["ap_document_root_ptr"])
        return ap_document_root

    def parse_apr_sockaddr_t(self, proc_layer:TranslationLayerInterface, apr_sockaddr_t_addr:int):
        pool_ptr = self.read_pointer(proc_layer, apr_sockaddr_t_addr + self.apr_sockaddr_t_offsets["pool_ptr"]) 
        #print("                     pool_ptr:", pool_ptr)
        hostname_ptr = self.read_pointer(proc_layer, apr_sockaddr_t_addr + self.apr_sockaddr_t_offsets["hostname_ptr"]) 
        #print("                     hostname_ptr", hostname_ptr)
        servname_ptr = self.read_pointer(proc_layer, apr_sockaddr_t_addr + self.apr_sockaddr_t_offsets["servname_ptr"]) 
        #print("                     servname_ptr", servname_ptr)
        port = self.read_n_bytes(proc_layer, apr_sockaddr_t_addr + self.apr_sockaddr_t_offsets["port"], 2) 
        #print("                     port", port)
        family = self.read_n_bytes(proc_layer, apr_sockaddr_t_addr + self.apr_sockaddr_t_offsets["family"], 4)
        #print("                     family", family)
        salen = self.read_int(proc_layer, apr_sockaddr_t_addr + self.apr_sockaddr_t_offsets["salen"])
        #print("                     salen", salen)
        ipaddr_len = self.read_int(proc_layer, apr_sockaddr_t_addr + self.apr_sockaddr_t_offsets["ipaddr_len"])
        #print("                     ipaddr_len", ipaddr_len)
        addr_str_len = self.read_int(proc_layer, apr_sockaddr_t_addr + self.apr_sockaddr_t_offsets["addr_str_len"])
        #print("                     addr_str_len", addr_str_len)
        ipaddr_ptr = self.read_pointer(proc_layer, apr_sockaddr_t_addr + self.apr_sockaddr_t_offsets["ipaddr_ptr"]) 
        #print("                     ipaddr_ptr", ipaddr_ptr)

        return family, ipaddr_len
        
    def parse_server_addr_rec(self, proc_layer:TranslationLayerInterface, server_addr_rec_addr:int):
        next_ptr = self.read_pointer(proc_layer, server_addr_rec_addr + self.server_addr_rec_offsets["next_ptr"])
        #print("             next_ptr:        ", format(next_ptr, '#04x'))

        virthost = self.get_pointer_and_read_string(proc_layer, server_addr_rec_addr + self.server_addr_rec_offsets["virthost_ptr"])
        #print("             virthost:        ", virthost)

        host_addr_ptr = self.read_pointer(proc_layer, server_addr_rec_addr + self.server_addr_rec_offsets["host_addr_ptr"])
        #print("             host_addr_ptr:   ", format(host_addr_ptr, '#04x'))

        #self.parse_apr_sockaddr_t(proc_layer, host_addr_ptr)

        port = self.read_int(proc_layer, server_addr_rec_addr + self.server_addr_rec_offsets["host_port"])
        #print("             port:            ", port)

        family, ipaddr_len = self.parse_apr_sockaddr_t(proc_layer, host_addr_ptr)

        return virthost, port, family, ipaddr_len



    def parse_server(self, proc_layer:TranslationLayerInterface, task:task_struct, server_rec_addr:int):
        server_hostname = self.get_pointer_and_read_string(proc_layer, server_rec_addr + self.server_rec_offsets["server_hostname_ptr"])
 
        defn_name = self.get_pointer_and_read_string(proc_layer, server_rec_addr + self.server_rec_offsets["defn_name_ptr"])

        error_fname = self.get_pointer_and_read_string(proc_layer, server_rec_addr + self.server_rec_offsets["error_fname_ptr"])

        server_admin = self.get_pointer_and_read_string(proc_layer, server_rec_addr + self.server_rec_offsets["server_admin_ptr"])


        names_ptr = self.read_pointer(proc_layer, server_rec_addr + self.server_rec_offsets["names_ptr"])
        names = self.parse_apr_array_header_t(proc_layer, names_ptr)

        wild_names_ptr = self.read_pointer(proc_layer, server_rec_addr + self.server_rec_offsets["wild_names_ptr"])
        wild_names = self.parse_apr_array_header_t(proc_layer, wild_names_ptr)


        addrs_ptr = self.read_pointer(proc_layer, server_rec_addr + self.server_rec_offsets["addrs_ptr"])
        if addrs_ptr:
            virthost, port, family, ipaddr_len = self.parse_server_addr_rec(proc_layer, addrs_ptr)

        
        module_config_ptr = self.read_pointer(proc_layer, server_rec_addr + self.server_rec_offsets["module_config_ptr"])
        core_server_config_ptr = self.get_core_server_config_addr(proc_layer, module_config_ptr)
        ap_document_root = self.parse_core_server_config(proc_layer, core_server_config_ptr)

        relevant_values = self.format_output([server_hostname, names, wild_names, ap_document_root, defn_name, error_fname, server_admin, virthost, port])

        yield (
                    0,
                    (
                        task.pid,
                        relevant_values[0],
                        relevant_values[1],
                        relevant_values[2],
                        relevant_values[3],
                        relevant_values[4],
                        relevant_values[5],
                        relevant_values[6],
                        relevant_values[7],
                        relevant_values[8],
                    ),
                )



    def _find_server_rec_addrs(self, proc_layer:TranslationLayerInterface, task:task_struct):
        # Basisadressen der gefundenen apr_pool_t Strukturen
        #print("findsever")
        apr_pool_t_addrs = self.get_apr_pool_t_addrs(proc_layer, task)
        if not apr_pool_t_addrs:
            return
        #print("apr_pool_t_addrs", apr_pool_t_addrs)
        
        #Basisadressen der gefundenen process_rec Strukturen
        process_rec_addrs = self.get_process_rec_addrs(proc_layer, task, apr_pool_t_addrs)
        if not process_rec_addrs:
            return

        #print("process_rec_addrs",process_rec_addrs)

        server_rec_addrs = self.get_server_rec_addrs(proc_layer, task, process_rec_addrs)
        if not server_rec_addrs:
            return
        
        #print("server_rec_addrssssss", server_rec_addrs)

        return server_rec_addrs



    def _generator(self, tasks):
        vmlinux = self.context.modules[self.config["kernel"]]
        is_32bit = not symbols.symbol_table_is_64bit(
            self.context, vmlinux.symbol_table_name
        )
        if is_32bit:
            #print("\n32 bit!")
            self.set_offsets_for_32bit()
        else:
            #print("\n64 bit!")
            self.set_offsets_for_64bit()

         # Iteriert über alle prozesse
        for task in tasks:
            task_name = utility.array_to_string(task.comm)
            if task_name not in ("apache2", "httpd"):
                continue

            #print("task_name", task_name)
            proc_layer_name = task.add_process_layer()
            if not proc_layer_name:
                continue

            proc_layer = self.context.layers[proc_layer_name]

            server_rec_addrs = self._find_server_rec_addrs(proc_layer, task)

            if not server_rec_addrs:
                continue

            for server_rec_addr in server_rec_addrs:
                #print("server_rec_addr", server_rec_addr)
                gen = self.parse_server(proc_layer, task, server_rec_addr)

                for el in gen:
                    yield el
                

    def run(self):
        # Spezifiziert die Output-Spalten
        columns = [
            ("PID", int),
            ("Hostname", str),
            ("Aliases", str),
            ("Aliases_wildcard", str),
            ("Document_root", str),
            ("defn_name", str),
            ("Error_Log", str),
            ("Server_admin", str),
            ("Virthost", str),
            ("Port", str),
        ]

        return renderers.TreeGrid(
            columns,
            self._generator(
                pslist.PsList.list_tasks(
                    self.context, self.config["kernel"]
                )
            ),
        )


class Connections(Configuration):
    _required_framework_version = (2, 0, 0)
    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            # Specifies the OS for which the ülugin was built
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            # Specifies the dependency for the pslist-plugin
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
        ]

    # Validiert potenzielle conn_rec Adressen.
    # Params:   conn_rec_addr -> potenzielle Startadresse für ein conn_rec.
    # Returns:  True, wenn es sich wahrscheinlich um ein conn_rec handelt.
    #           False, sonst.
    def is_conn_rec_valid(self, proc_layer, conn_rec_addr):
        try: 
            # local_addr_ptr ist ein Pointer auf ein apr_sockaddr_r
            local_addr_ptr = self.read_pointer(proc_layer, conn_rec_addr + self.conn_rec_offsets["local_addr_ptr"])
            if not local_addr_ptr:
                return False
        
            if not self.is_apr_sockaddr_t_valid(proc_layer, local_addr_ptr):
               return False
            
            # client_addr_ptr ist ein Pointer auf ein apr_sockaddr_r
            client_addr_ptr = self.read_pointer(proc_layer, conn_rec_addr + self.conn_rec_offsets["client_addr_ptr"])
            if not client_addr_ptr:
                return False
            if not self.is_apr_sockaddr_t_valid(proc_layer, client_addr_ptr):
                return False

            double_reverse = self.read_int(proc_layer, conn_rec_addr + self.conn_rec_offsets["double_reverse"])
            #print("double_reverse", double_reverse)
            aborted = self.read_int(proc_layer, conn_rec_addr + self.conn_rec_offsets["aborted"])
            #print("aborted", aborted)
            keepalive = self.read_int(proc_layer, conn_rec_addr + self.conn_rec_offsets["keepalive"])
            #print("keepalive", keepalive)
            keepalives = self.read_int(proc_layer, conn_rec_addr + self.conn_rec_offsets["keepalives"])
            #print("keepalives", keepalives)

            # keepalive ist ein enum mit 3 Werten
            keepalive = self.read_int(proc_layer, conn_rec_addr + self.conn_rec_offsets["keepalive"])
            #print("keepalive", keepalive)
            if keepalive not in [0, 1, 2]:
                return False
          
            return True
        except Exception as e: 
            print("Fehler in is_conn_rec_valid:", e)
            return False


     
    # Findet mögliche Startadresse von conn_rec Strukturen.
    # Params:   server_rec_addrs: Gefundene mögliche Startadressen von server_rec Strukten.
    # Returns:  Null, falls keine gefunden wurden.
    #           Liste der möglichen Startadressen der conn_rec Strukturen, sonst.
    def get_conn_rec_addrs(self, proc_layer, task, server_rec_addrs):
        # server_rec_ptr_addrs enthält die Adressen, an denen ein Pointer auf die vermuteten server_rec Strukturen gefunden wurden
        server_rec_ptr_addrs = []
        for server_rec_addr in server_rec_addrs:
            for addr in proc_layer.scan(
                self.context,
                scanners.BytesScanner(struct.pack(self.pack_format, server_rec_addr)),
                sections=task.get_process_memory_sections(),
            ):
                server_rec_ptr_addrs.append(addr)
    
        if server_rec_ptr_addrs == []:
            return

        # potential_conn_rec_addrs enthält die potenziellen Startadressen der conn_rec Strukturen.
        # Der gefundene Pointer hat in conn_rec das Offset 8
        potential_conn_rec_addrs = []
        for server_rec_ptr_addr in server_rec_ptr_addrs:
            potential_conn_rec_addrs.append(server_rec_ptr_addr - self.conn_rec_offsets["base_server_ptr"])

        #print("potential_conn_rec_addrs", potential_conn_rec_addrs)


        
        # conn_rec_addrs enthält die nach einer validierung übrig gebliebenen Startadressen auf die conn_rec Strukturen
        conn_rec_addrs = []
        for potential_conn_rec_addr in potential_conn_rec_addrs:
            if(self.is_conn_rec_valid(proc_layer, potential_conn_rec_addr)):
                conn_rec_addrs.append(potential_conn_rec_addr)
        
        if conn_rec_addrs == []:
            return 
        
        #print("conn_rec_addrs", conn_rec_addrs)
        
        return conn_rec_addrs




    def parse_connection(self, proc_layer, task, conn_rec_addr):
        
        """
            # local address
            "local_addr_ptr":           24,
            # remote address; this is the end-point of the next hop, for the address of the request creator, see useragent_addr in request_rec
            "client_addr_ptr":          32,
            
            # Client's DNS name, if known.  NULL if DNS hasn't been checked, "" if it has and no address was found.  N.B. Only access this though get_remote_host() 
            "remote_host_ptr":          48,
            # Only ever set if doing rfc1413 lookups.  N.B. Only access this through get_remote_logname()
            "remote_logname_ptr":       56,
            
            # used for ap_get_server_name when UseCanonicalName is set to DNS (ignores setting of HostnameLookups)
            "local_host_ptr":           72,

            
            # Config vector containing pointers to connections per-server config structures.
            "conn_config_ptr":          88,
            
            # The bucket allocator to use for all bucket/brigade creations
            "bucket_alloc_ptr":         128,
            # The current state of this connection; may be NULL if not used by MPM
            "cs_ptr":                   136,
           
            
         
        """
        # Client's IP address; this is the end-point of the next hop, for the IP of the request creator, see useragent_ip in request_rec
        client_ip = self.get_pointer_and_read_string(proc_layer, conn_rec_addr + self.conn_rec_offsets["client_ip_ptr"])
        
        # server IP address
        local_ip = self.get_pointer_and_read_string(proc_layer, conn_rec_addr + self.conn_rec_offsets["local_ip_ptr"])

        # Are we still talking?
        aborted = self.read_int(proc_layer, conn_rec_addr + self.conn_rec_offsets["aborted"])
        # Are we going to keep the connection alive for another request? @see ap_conn_keepalive_e
        keepalive = self.read_int(proc_layer, conn_rec_addr + self.conn_rec_offsets["keepalive"])
        # How many times have we used it?
        keepalives = self.read_int(proc_layer, conn_rec_addr + self.conn_rec_offsets["keepalives"])
        #print("\naborted", aborted)
        #print("keepalive", keepalive)
        #print("keepalives", keepalives)
        #print("\nVerbindung entdeckt von ", client_ip, "nach", local_ip, "\n")
    
        relevant_values = self.format_output([client_ip, local_ip, aborted, keepalive, keepalives])

        yield (
                    0,
                    (
                        task.pid,
                        relevant_values[0],
                        relevant_values[1],
                        relevant_values[2],
                        relevant_values[3],
                        relevant_values[4],
                    ),
                )



    def _find_conn_rec_addrs(self, proc_layer, task):
        server_rec_addrs = self._find_server_rec_addrs(proc_layer, task)
        if not server_rec_addrs:
            #print("nichts")
            return
        
        #print(server_rec_addrs)

        conn_rec_addrs = self.get_conn_rec_addrs(proc_layer, task, server_rec_addrs)
        if not conn_rec_addrs:
            return
        
        return conn_rec_addrs

    def _generator(self, tasks):
        vmlinux = self.context.modules[self.config["kernel"]]
        is_32bit = not symbols.symbol_table_is_64bit(
            self.context, vmlinux.symbol_table_name
        )
        if is_32bit:
            #print("\n32 bit!")
            self.set_offsets_for_32bit()
        else:
            #print("\n64 bit!")
            self.set_offsets_for_64bit()

         # Iteriert über alle prozesse
        for task in tasks:
            task_name = utility.array_to_string(task.comm)
            if task_name not in ("apache2", "httpd"):
                continue
            
            #print("task_name", task_name)
            proc_layer_name = task.add_process_layer()
            if not proc_layer_name:
                continue

            proc_layer = self.context.layers[proc_layer_name]

            conn_rec_addrs = self._find_conn_rec_addrs(proc_layer, task)
            if not conn_rec_addrs:
                continue

            for conn_rec_addr in conn_rec_addrs:
                gen = self.parse_connection(proc_layer, task, conn_rec_addr)

                for el in gen:
                    yield el



            

    def run(self):
        # Spezifiziert die Output-Spalten
        columns = [
            ("PID", int),
            ("client_ip", str),
            ("local_ip", str),
            ("aborted", str),
            ("keepalive", str),
            ("keepalives", str),
        ]

        return renderers.TreeGrid(
            columns,
            self._generator(
                pslist.PsList.list_tasks(
                    self.context, self.config["kernel"]
                )
            ),
        )


class Requests(Connections):
    _required_framework_version = (2, 0, 0)
    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            # Specifies the OS for which the ülugin was built
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            # Specifies the dependency for the pslist-plugin
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
        ]
    
           
    def is_request_rec_valid(self, proc_layer, request_rec_addr, server_rec_addrs=None, conn_rec_addrs=None):
        try:
            if server_rec_addrs:
                server_ptr = self.read_pointer(proc_layer, request_rec_addr + self.request_rec_offsets["server_ptr"])
                if not server_ptr in server_rec_addrs:
                    return False
                
            if conn_rec_addrs:
                connection_ptr = self.read_pointer(proc_layer, request_rec_addr + self.request_rec_offsets["connection_ptr"])
                if not connection_ptr in conn_rec_addrs:
                    return False

            header_only = self.read_int(proc_layer, request_rec_addr + self.request_rec_offsets["header_only"])
            #print("header_only", header_only)
            if header_only not in [0, 1]:
                return False
            
            proto_num = self.read_int(proc_layer, request_rec_addr + self.request_rec_offsets["proto_num"])
            #print("proto_num", proto_num)
            if proto_num not in [1000, 1001, 2000, 3000]:
                return False

            status = self.read_int(proc_layer, request_rec_addr + self.request_rec_offsets["status"])
            #print("status", status)
            if status not in [200, 404]:
                return False

            # In manchen Fällen gab es einen Pointer auf die header Strukturen.
            # Allerding wirft Volatility bei dem Zugriff auf diese Adressen einen Fehler. Da sonst auch keine releventen Informationen vorhanden sind,
            # werden diese als nicht valide betrachtet
            """
            try:
                headers_in_ptr = self.read_pointer(proc_layer, request_rec_addr + self.request_rec_offsets["headers_in_ptr"])
                if headers_in_ptr:
                    proc_layer.read(headers_in_ptr, 1)

                headers_out_ptr = self.read_pointer(proc_layer, request_rec_addr + self.request_rec_offsets["headers_out_ptr"])
                if headers_out_ptr:
                    proc_layer.read(headers_out_ptr, 1)

                err_headers_out_ptr = self.read_pointer(proc_layer, request_rec_addr + self.request_rec_offsets["err_headers_out_ptr"])
                if err_headers_out_ptr:
                    proc_layer.read(err_headers_out_ptr, 1)

                body_table_ptr = self.read_pointer(proc_layer, request_rec_addr + self.request_rec_offsets["body_table_ptr"])
                if body_table_ptr:
                    proc_layer.read(body_table_ptr, 1)
            except Exception as e:
                print("Exception", e)
                return False
            """
            
            #request = self.get_pointer_and_read_string(proc_layer, request_rec_addr + self.request_rec_offsets["the_request_ptr"])
            #print("request", request)

            return True
        except Exception as e: 
            print("Fehler in is_request_rec_valid:", e)
            return False

    def get_yara_search_request_rec_addrs(self, proc_layer, server_rec_addrs=None, conn_rec_addrs=None):
        """
            /** A proxy request (calculated during post_read_request/translate_name)
            *  possible values PROXYREQ_NONE, PROXYREQ_PROXY, PROXYREQ_REVERSE,
            *                  PROXYREQ_RESPONSE
            */
            int proxyreq;               # (00 | 01 | 02 | 03) 00 00 00
            
            /** HEAD request, as opposed to GET */
            int header_only;            # (00 | 01) 00 00 00

            /** Protocol version number of protocol; 1.1 = 1001 */
            /** 
            1.0 = 1000
            2.0 = 2000
            3.0 = 2000
            */
            int proto_num;              # E9 03 00 00 | E8 03 00 00 | D0 07 00 00 | B8 0B 00 00 = (E9 03 | E8 03 | D0 07 | B8 0B) 00 00 

            const char *protocol;       # [8]
            const char *hostname;       # [8]
            apr_time_t request_time;    # [8]
            const char *status_line;    # [8]

            /** Status line */
            int status;                 # ((94 01) | (C8 00)) 00 00
        """
        # Wenn 64 bit
        if self.pack_format == "Q":
            request_rec_rule = yara.compile(source='rule request_rec {strings: $a = {(00 | 01 | 02 | 03) 00 00 00 (00 | 01) 00 00 00 (E9 03 | E8 03 | D0 07 | B8 0B) 00 00 [8] [8] [8] [8] ((94 01) | (C8 00)) 00 00} condition: $a}')
        else:
            request_rec_rule = yara.compile(source='rule request_rec {strings: $a = {(00 | 01 | 02 | 03) 00 00 00 (00 | 01) 00 00 00 (E9 03 | E8 03 | D0 07 | B8 0B) 00 00 [4] [4] [8] [4] ((94 01) | (C8 00)) 00 00} condition: $a}')
       
        potential_request_rec_addrs = []
        for offset, rule_name, name, value in proc_layer.scan(
            context=self.context, scanner=yarascan.YaraScanner(rules=request_rec_rule)
            ):
                request_rec_addr = offset - self.request_rec_offsets["proxyreq"]
                potential_request_rec_addrs.append(request_rec_addr)

        #print("potential_request_rec_addrs", potential_request_rec_addrs)

        request_rec_addrs = []
        for potential_request_rec_addr in potential_request_rec_addrs:
            if self.is_request_rec_valid(proc_layer, potential_request_rec_addr, server_rec_addrs, conn_rec_addrs):
                request_rec_addrs.append(potential_request_rec_addr)
        
        #print(request_rec_addrs)
        return request_rec_addrs


    
    def get_request_rec_addrs(self, proc_layer, task, conn_rec_addrs, server_rec_addrs):
        # server_rec_ptr_addrs enthält die Adressen, an denen ein Pointer auf die vermuteten server_rec Strukturen gefunden wurden
        server_rec_ptr_addrs = []
        for server_rec_addr in server_rec_addrs:
            for addr in proc_layer.scan(
                self.context,
                scanners.BytesScanner(struct.pack(self.pack_format, server_rec_addr)),
                sections=task.get_process_memory_sections(),
            ):
                server_rec_ptr_addrs.append(addr)

        # server_rec_ptr_addrs enthält die Adressen, an denen ein Pointer auf die vermuteten server_rec Strukturen gefunden wurden
        conn_rec_ptr_addrs = []
        for conn_rec_addr in conn_rec_addrs:
            for addr in proc_layer.scan(
                self.context,
                scanners.BytesScanner(struct.pack(self.pack_format, conn_rec_addr)),
                sections=task.get_process_memory_sections(),
            ):
                conn_rec_ptr_addrs.append(addr)

        potential_request_rec_addrs_1 = []
        for server_rec_ptr_addr in server_rec_ptr_addrs:
            potential_request_rec_addrs_1.append(server_rec_ptr_addr - 16)

        potential_request_rec_addrs_2 = []
        for conn_rec_ptr_addr in conn_rec_ptr_addrs:
            potential_request_rec_addrs_2.append(conn_rec_ptr_addr - 8)

        potential_request_rec_addrs = list(set(potential_request_rec_addrs_1) & set(potential_request_rec_addrs_2))

        
        print("potential_request_rec_addrs", potential_request_rec_addrs)

        request_rec_addrs = []
        for potential_request_rec_addr in potential_request_rec_addrs:
            if(self.is_request_rec_valid(proc_layer, potential_request_rec_addr)):
                request_rec_addrs.append(potential_request_rec_addr)
        
        if request_rec_addrs == []:
            return 
        #print("request_rec_addrs", request_rec_addrs)
        
        return request_rec_addrs


    """
    def parse_apr_table_t(self, proc_layer, apr_table_t_addr):
        apr_table_t_offsets = {
            "apr_table_elts_ptr":    0,
            "apr_is_empty_table":   8,
            "apr_is_empty_array":   12,
        }

        apr_table_elts_ptr = self.read_pointer(proc_layer, apr_table_t_addr + apr_table_t_offsets["apr_table_elts_ptr"])
        print(f"     apr_table_elts_ptr:  0x{apr_table_elts_ptr:02x}")

        apr_is_empty_table = self.read_int(proc_layer, apr_table_t_addr + apr_table_t_offsets["apr_is_empty_table"])
        print("     apr_is_empty_table", apr_is_empty_table)

        apr_is_empty_array = self.read_pointer(proc_layer, apr_table_t_addr + apr_table_t_offsets["apr_is_empty_array"])
        print("     apr_is_empty_array", apr_is_empty_array)

        self.parse_apr_array_header_t(proc_layer, apr_table_elts_ptr)
"""
    def parse_request(self, proc_layer, task, request_rec_addr):
        pool_ptr = self.read_pointer(proc_layer, request_rec_addr + self.request_rec_offsets["pool_ptr"])
        #print(f'pool_pointer: \t\t0x{pool_ptr:02x}')

        connection_ptr = self.read_pointer(proc_layer, request_rec_addr + self.request_rec_offsets["connection_ptr"])
        #print(f'connection_pointer: \t0x{connection_ptr:02x}')

        server_ptr = self.read_pointer(proc_layer, request_rec_addr + self.request_rec_offsets["server_ptr"])
        #print(f'server_ptr: \t\t0x{server_ptr:02x}')

        next_ptr = self.read_pointer(proc_layer, request_rec_addr + self.request_rec_offsets["next_ptr"])

        proxyreq = self.read_int(proc_layer, request_rec_addr + self.request_rec_offsets["proxyreq"])
        #print(f'proxy_request: \t\t{proxyreq}')

        header_only = self.read_int(proc_layer, request_rec_addr + self.request_rec_offsets["header_only"])
        #print(f'header_only: \t\t{header_only}')

        proto_num = self.read_int(proc_layer, request_rec_addr + self.request_rec_offsets["proto_num"])
        #print(f'proto_num: \t\t{proto_num}')

        protocol = self.get_pointer_and_read_string(proc_layer, request_rec_addr + self.request_rec_offsets["protocol_ptr"])
        #print(f'protocol:  {protocol}')

        hostname = self.get_pointer_and_read_string(proc_layer, request_rec_addr + self.request_rec_offsets["hostname_ptr"])
        #print(f'hostname: {hostname}')
        
        # read_pointer ließt 8 Bytes und wandelt es in int um. 
        # Da es sich hier um einen 8 Byte int handelt kann die Methode verwendet werden, auch wenn kein Pointer gehohlt wird.
        request_time = self.read_n_bytes(proc_layer, request_rec_addr + self.request_rec_offsets["request_time"], 8)
        request_time_readable = datetime.datetime.utcfromtimestamp(request_time / 1000000).strftime("%Y-%m-%d %H:%M:%S")
        #print(f'request_time (Unix Timestamp in Microseconds): {request_time}')
        #print(f'request_time (Unix Timestamp in lesbar):       {request_time_readable}')
    
        status_line = self.get_pointer_and_read_string(proc_layer, request_rec_addr + self.request_rec_offsets["status_line_ptr"])
        #print(f'status_line: {status_line}')

        status = self.read_int(proc_layer, request_rec_addr + self.request_rec_offsets["status"])
        #print(f'status: \t\t{status}')

        method_number = self.read_int(proc_layer, request_rec_addr + self.request_rec_offsets["method_number"])
        #print(f'method_number: \t\t{method_number}')

        method = self.get_pointer_and_read_string(proc_layer, request_rec_addr + self.request_rec_offsets["method_ptr"])
        #print(f'method:  {method}')

        body_table_ptr = self.read_pointer(proc_layer, request_rec_addr + self.request_rec_offsets["body_table_ptr"])
        #print(f'body_table_ptr: \t{body_table_ptr:2x}')

        body_table = self.parse_apr_array_header_t(proc_layer, body_table_ptr)

        headers_in_ptr = self.read_pointer(proc_layer, request_rec_addr + self.request_rec_offsets["headers_in_ptr"])
        #print(f'headers_in_ptr: \t{headers_in_ptr:2x}')

        headers_in = self.parse_apr_array_header_t(proc_layer, headers_in_ptr)

        headers_out_ptr = self.read_pointer(proc_layer, request_rec_addr + self.request_rec_offsets["headers_out_ptr"])
        #print(f'headers_out_ptr: \t{headers_out_ptr:2x}')

        headers_out = self.parse_apr_array_header_t(proc_layer, headers_out_ptr)

        err_headers_out_ptr = self.read_pointer(proc_layer, request_rec_addr + self.request_rec_offsets["err_headers_out_ptr"])
        #print(f'err_headers_out_ptr: \t{err_headers_out_ptr:2x}')

        err_headers_out = self.parse_apr_array_header_t(proc_layer, err_headers_out_ptr)

        content_type = self.get_pointer_and_read_string(proc_layer, request_rec_addr + self.request_rec_offsets["content_type_ptr"])
        #print(f'content_type: {content_type}')

        
        unparsed_uri = self.get_pointer_and_read_string(proc_layer, request_rec_addr + self.request_rec_offsets["unparsed_uri_ptr"])
        #print(f'unparsed_uri: {unparsed_uri}')

        uri = self.get_pointer_and_read_string(proc_layer, request_rec_addr + self.request_rec_offsets["uri_ptr"])
        #print(f'uri: {uri}')

        filename = self.get_pointer_and_read_string(proc_layer, request_rec_addr + self.request_rec_offsets["filename_ptr"])
        #print(f'filename: {filename}')

        canonical_filename = self.get_pointer_and_read_string(proc_layer, request_rec_addr + self.request_rec_offsets["canonical_filename_ptr"])
        #print(f'canonical_filename: {canonical_filename}')

        path_info = self.get_pointer_and_read_string(proc_layer, request_rec_addr + self.request_rec_offsets["path_info_ptr"])
        #print(f'path_info: {path_info}')

        args_ptr = self.read_pointer(proc_layer, request_rec_addr + self.request_rec_offsets["args_ptr"])
        #print(f'args_ptr: \t{args_ptr:2x}')

        
        proto_output_filters_ptr = self.read_pointer(proc_layer, request_rec_addr + self.request_rec_offsets["proto_output_filters_ptr"])
        #print(f'proto_output_filters_ptr: \t{proto_output_filters_ptr:2x}')

        # parse_filter(*find_file_and_offset_for_address(files, proto_output_filters_ptr, pid), files, 1)

        #client_ip, local_ip = get_ips_from_connection(*find_file_and_offset_for_address(files, connection_pointer, pid), files)

        #print(f'[-] {client_ip} -> {local_ip}: {method} {uri} [{status_line}]')

        relevant_values = self.format_output([request_rec_addr, next_ptr, request_time_readable, protocol, method, status, 
                                              uri, hostname, canonical_filename, headers_in, headers_out, err_headers_out, body_table])

        yield (
                    0,
                    (
                        task.pid,
                        format_hints.Hex(relevant_values[0]),
                        format_hints.Hex(relevant_values[1]),
                        relevant_values[2],
                        relevant_values[3],
                        relevant_values[4],
                        relevant_values[5],
                        relevant_values[6],
                        relevant_values[7],
                        relevant_values[8],
                        relevant_values[9],
                        relevant_values[10],
                        relevant_values[11],
                        relevant_values[12],
                    ),
                )
 
    def _generator(self, tasks):
        vmlinux = self.context.modules[self.config["kernel"]]
        is_32bit = not symbols.symbol_table_is_64bit(
            self.context, vmlinux.symbol_table_name
        )
        if is_32bit:
            #print("\n32 bit!")
            self.set_offsets_for_32bit()
        else:
            #print("\n64 bit!")
            self.set_offsets_for_64bit()

         # Iteriert über alle prozesse
        for task in tasks:
            task_name = utility.array_to_string(task.comm)
            if task_name not in ("apache2", "httpd"):
                continue

            proc_layer_name = task.add_process_layer()
            if not proc_layer_name:
                continue

            proc_layer = self.context.layers[proc_layer_name]

            

            server_rec_addrs = self._find_server_rec_addrs(proc_layer, task)
            if not server_rec_addrs:
                continue

            #print("server_rec_addrs", server_rec_addrs)

            conn_rec_addrs = self._find_conn_rec_addrs(proc_layer, task)
            if not conn_rec_addrs:
                continue
           
            #print("conn_rec_addrs", conn_rec_addrs)

            yara_search_request_rec_addrs = self.get_yara_search_request_rec_addrs(proc_layer, server_rec_addrs, conn_rec_addrs)

            for yara_search_request_rec_addr in yara_search_request_rec_addrs:
                gen = self.parse_request(proc_layer, task, yara_search_request_rec_addr)

                for el in gen:
                    yield el




    def run(self):
        # Spezifiziert die Output-Spalten
        columns = [
            ("PID", int),
            ("Addr",format_hints.Hex),
            ("Next", format_hints.Hex),
            ("request_time_readable", str),
            ("protocol", str),
            ("method", str),
            ("status", str),
            ("uri", str),
            ("hostname", str),
            ("canonical_filename", str),
            ("headers_in", str),
            ("headers_out", str),
            ("err_headers_out", str),
            ("body_table", str),
        ]

        return renderers.TreeGrid(
            columns,
            self._generator(
                pslist.PsList.list_tasks(
                    self.context, self.config["kernel"]
                )
            ),
        )


class Content(interfaces.plugins.PluginInterface, CommonApacheStuff):
    _required_framework_version = (2, 0, 0)
    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            # Specifies the OS for which the ülugin was built
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            # Specifies the dependency for the pslist-plugin
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
        ]
    


    def is_apr_bucket_type_t_valid(self, proc_layer, apr_bucket_type_t_addr):
        try:
            is_metadata = self.read_int(proc_layer, apr_bucket_type_t_addr + self.apr_bucket_type_t_offsets["is_metadata"])
            #print("is_metadata", is_metadata)
            if is_metadata not in [0, 1]:
                return False

            return True
        except Exception as e: 
            print("Fehler in is_apr_bucket_type_t_valid:", e)
            return False
    
    def is_apr_bucket_type_heap_valid(self, proc_layer, apr_bucket_type_t_addr):
        try:
            # Prüft, ob es ein apr_bucket_type_t sein kann
            if not self.is_apr_bucket_type_t_valid(proc_layer, apr_bucket_type_t_addr):
                return False
            
            # Prüft, ob es ein apr_bucket_type_heap sein kann
            num_func = self.read_int(proc_layer, apr_bucket_type_t_addr + self.apr_bucket_type_t_offsets["num_func"])
            #print("num_func", num_func)
            if num_func != 5:
                return False

            return True
        except Exception as e: 
            print("Fehler in is_apr_bucket_type_heap_valid:", e)
            return False
    
    def is_apr_bucket_type_file_valid(self, proc_layer, apr_bucket_type_t_addr):
        try:
            # Prüft, ob es ein apr_bucket_type_t sein kann
            if not self.is_apr_bucket_type_t_valid(proc_layer, apr_bucket_type_t_addr):
                return False
            
            # Prüft, ob es ein apr_bucket_type_file sein kann
            num_func = self.read_int(proc_layer, apr_bucket_type_t_addr + self.apr_bucket_type_t_offsets["num_func"])
            #print("num_func", num_func)
            if num_func != 5:
                return False

            return True
        except Exception as e: 
            print("Fehler in is_apr_bucket_type_file_valid:", e)
            return False

    def is_apr_bucket_valid(self, proc_layer, apr_bucket_addr):
        try:
            length = self.read_int(proc_layer, apr_bucket_addr + self.apr_bucket_offsets["length"])
            #print("length", length)
            start = self.read_int(proc_layer, apr_bucket_addr + self.apr_bucket_offsets["start"])
            #print("start", start)

            data_ptr = self.read_pointer(proc_layer, apr_bucket_addr + self.apr_bucket_offsets["data_ptr"])
            #print("data_ptr", data_ptr)

            return True
        except Exception as e: 
            print("Fehler in is_apr_bucket_valid:", e)
            return False

        

    def get_apr_bucket_type_heap_addrs(self, proc_layer, task):
        # heap_string_addrs enthält die Adressen, an denen der String 'HEAP' gefunden wurde
        heap_string_addrs = []
        for address in proc_layer.scan(
            self.context,
            scanners.BytesScanner(b"HEAP"),
            sections=task.get_process_memory_sections(),
        ):
            heap_string_addrs.append(address)
        
        if heap_string_addrs == []:
            return
        #print("heap_string_addrs", heap_string_addrs)
        # heap_string_ptr_addrs enthält die gefundenen Adressen der Pointer, welche auf die HEAP Strings zeigen
        heap_string_ptr_addrs = []
        for heap_string_addr in heap_string_addrs:
            for addr in proc_layer.scan(
                self.context,
                scanners.BytesScanner(struct.pack(self.pack_format, heap_string_addr)),
                sections=task.get_process_memory_sections(),
            ):
                heap_string_ptr_addrs.append(addr)

        #print("heap_string_ptr_addrs", heap_string_ptr_addrs)
        if heap_string_ptr_addrs == []:
            return

        
        # potential_apr_bucket_type_heap_addrs enthält die Startadressen von den vermuteten apr_bucket_type_heap Structs.
        # Diese starten mit der Adresse von dem gefundenen Pointer
        potential_apr_bucket_type_heap_addrs = heap_string_ptr_addrs

        #print("potential_apr_bucket_type_heap_addrs", potential_apr_bucket_type_heap_addrs)
        apr_bucket_type_heap_addrs = []
        for potential_apr_bucket_type_heap_addr in potential_apr_bucket_type_heap_addrs:
            if(self.is_apr_bucket_type_heap_valid(proc_layer, potential_apr_bucket_type_heap_addr)):
                apr_bucket_type_heap_addrs.append(potential_apr_bucket_type_heap_addr)
        
        if apr_bucket_type_heap_addrs == []:
            return 
        
        return apr_bucket_type_heap_addrs

    def get_apr_bucket_type_file_addrs(self, proc_layer, task):
        # file_string_addrs enthält die Adressen, an denen der String 'FILE' gefunden wurde
        file_string_addrs = []
        for address in proc_layer.scan(
            self.context,
            scanners.BytesScanner(b"FILE"),
            sections=task.get_process_memory_sections(),
        ):
            file_string_addrs.append(address)
        
        if file_string_addrs == []:
            return
        
        # file_string_ptr_addrs enthält die gefundenen Adressen der Pointer, welche auf die FILE Strings zeigen
        file_string_ptr_addrs = []
        for file_string_addr in file_string_addrs:
            for addr in proc_layer.scan(
                self.context,
                scanners.BytesScanner(struct.pack(self.pack_format, file_string_addr)),
                sections=task.get_process_memory_sections(),
            ):
                file_string_ptr_addrs.append(addr)

        if file_string_ptr_addrs == []:
            return

        
        # potential_apr_bucket_type_file_addrs enthält die Startadressen von den vermuteten apr_bucket_type_file Structs.
        # Diese starten mit der Adresse von dem gefundenen Pointer
        potential_apr_bucket_type_file_addrs = file_string_ptr_addrs

        apr_bucket_type_file_addrs = []
        for potential_apr_bucket_type_file_addr in potential_apr_bucket_type_file_addrs:
            if(self.is_apr_bucket_type_file_valid(proc_layer, potential_apr_bucket_type_file_addr)):
                apr_bucket_type_file_addrs.append(potential_apr_bucket_type_file_addr)
        
        if apr_bucket_type_file_addrs == []:
            return 
        
        return apr_bucket_type_file_addrs

    def get_apr_bucket_addrs(self, proc_layer, task, apr_bucket_type_t_addrs):
        # apr_bucket_type_heap_ptr_addrs enthält die gefundenen Adressen der Pointer, welche auf die pconf Strings zeigen
        apr_bucket_type_t_ptr_addrs = []
        for apr_bucket_type_t_addr in apr_bucket_type_t_addrs:
            for addr in proc_layer.scan(
                self.context,
                scanners.BytesScanner(struct.pack(self.pack_format, apr_bucket_type_t_addr)),
                sections=task.get_process_memory_sections(),
            ):
                apr_bucket_type_t_ptr_addrs.append(addr)

        if apr_bucket_type_t_ptr_addrs == []:
            return

        #print("apr_bucket_type_t_ptr_addrs", apr_bucket_type_t_ptr_addrs)
        # potential_apr_bucket_addrs enthält die Startadressen von den vermuteten apr_bucket Structs.
        # Diese starten mit dem Pointer auf die apr_bucket_type_t_ptr_addrs Structs
        potential_apr_bucket_addrs = apr_bucket_type_t_ptr_addrs

        apr_bucket_addrs = []
        for potential_apr_bucket_addr in potential_apr_bucket_addrs:
            if(self.is_apr_bucket_valid(proc_layer, potential_apr_bucket_addr)):
                apr_bucket_addrs.append(potential_apr_bucket_addr)
        
        if apr_bucket_addrs == []:
            return 
        
        return apr_bucket_addrs

    def get_apr_bucket_t_addrs(self, proc_layer, apr_bucket_addrs):        
        apr_bucket_t_addrs = []
        for apr_bucket_addr in apr_bucket_addrs:
            data_ptr = self.read_pointer(proc_layer, apr_bucket_addr + self.apr_bucket_offsets["data_ptr"])
            apr_bucket_t_addrs.append(data_ptr)

        #print("apr_bucket_t_addrs", apr_bucket_t_addrs)

        return apr_bucket_t_addrs



    def parse_apr_bucket_heap(self, proc_layer, task, apr_bucket_heap_addr):
        #print()
        refcount = self.read_int(proc_layer, apr_bucket_heap_addr + self.apr_bucket_heap_offsets["refcount"])
        #print("refcount:    ", refcount)

        alloc_len = self.read_int(proc_layer, apr_bucket_heap_addr + self.apr_bucket_heap_offsets["alloc_len"])
        #print("alloc_len:   ", alloc_len)

        #print("jetzt base")
        base = self.get_pointer_and_read_string(proc_layer, apr_bucket_heap_addr + self.apr_bucket_heap_offsets["base_ptr"])
        #print("Inhalt:", base)

        relevant_values = self.format_output([apr_bucket_heap_addr, base])

        yield (
                    0,
                    (
                        task.pid,
                        format_hints.Hex(relevant_values[0]),
                        relevant_values[1],
                    ),
                )


    def parse_apr_file_t(self, proc_layer, apr_file_t_addr):
        apr_file_t_offsets = {
            "pool_ptr": 0,
            "filedes":  8,
            "fname_ptr":    16,
        }

        fname = self.get_pointer_and_read_string(proc_layer, apr_file_t_addr + apr_file_t_offsets["fname_ptr"])
        print("fname", fname)

    def parse_apr_bucket_file(self, proc_layer, apr_bucket_heap_addr):
        print()
        refcount = self.read_int(proc_layer, apr_bucket_heap_addr + self.apr_bucket_file_offsets["refcount"])
        #print("refcount:    ", refcount)

        fd_ptr = self.read_pointer(proc_layer, apr_bucket_heap_addr + self.apr_bucket_file_offsets["fd_ptr"])
        #print("fd_ptr:   ", fd_ptr)

        if fd_ptr:
            self.parse_apr_file_t(proc_layer, fd_ptr)

        readpool_ptr = self.get_pointer_and_read_string(proc_layer, apr_bucket_heap_addr + self.apr_bucket_file_offsets["readpool_ptr"])
        #print("readpool_ptr:    ", readpool_ptr)

        can_map = self.read_int(proc_layer, apr_bucket_heap_addr + self.apr_bucket_file_offsets["can_map"])
        #print("can_map:    ", can_map)

    """
    def search_other_buckets(self, proc_layer, task, apr_bucket_addr):
        bucket_brigade_addr = self.read_pointer(proc_layer, apr_bucket_addr + self.apr_bucket_offsets["list_ptr"])
         # file_string_addrs enthält die Adressen, an denen der String 'FILE' gefunden wurde
        other_bucket_brigade_ptr_addrs = []
        for address in proc_layer.scan(
            self.context,
            scanners.BytesScanner(struct.pack("Q", bucket_brigade_addr)),
            sections=task.get_process_memory_sections(),
        ):
            other_bucket_brigade_ptr_addrs.append(address)
        
        if other_bucket_brigade_ptr_addrs == []:
            return
        
        other_bucket_addrs = []
        for other_bucket_brigade_ptr_addr in other_bucket_brigade_ptr_addrs:
            other_bucket_addrs.append(other_bucket_brigade_ptr_addr - self.apr_bucket_offsets["list_ptr"])
        
        if apr_bucket_addr in other_bucket_addrs:
            other_bucket_addrs.remove(apr_bucket_addr)

        if other_bucket_addrs == []:
            return
        print("Pointer anderer buckets:", other_bucket_addrs)

        valid_other_bucket_addrs = []
        for other_bucket_addr in other_bucket_addrs:
            if self.is_apr_bucket_valid(proc_layer, other_bucket_addr):
                valid_other_bucket_addrs.append(other_bucket_addr)

        print("Pointer auf die validierten anderen Buckets:", valid_other_bucket_addrs)
    """

    def _generator(self, tasks):
        vmlinux = self.context.modules[self.config["kernel"]]
        is_32bit = not symbols.symbol_table_is_64bit(
            self.context, vmlinux.symbol_table_name
        )
        if is_32bit:
            #print("\n32 bit!")
            self.set_offsets_for_32bit()
        else:
            #print("\n64 bit!")
            self.set_offsets_for_64bit()

         # Iteriert über alle prozesse
        for task in tasks:
            task_name = utility.array_to_string(task.comm)
            if task_name not in ("apache2", "httpd"):
                continue

            proc_layer_name = task.add_process_layer()
            if not proc_layer_name:
                continue

            proc_layer = self.context.layers[proc_layer_name]

            apr_bucket_type_heap_addrs = self.get_apr_bucket_type_heap_addrs(proc_layer, task)
            if not apr_bucket_type_heap_addrs:
                continue
            #print("apr_bucket_type_heap_addrs", apr_bucket_type_heap_addrs)
            


            apr_bucket_addrs = self.get_apr_bucket_addrs(proc_layer, task, apr_bucket_type_heap_addrs)
            if not apr_bucket_addrs:
                continue

            apr_bucket_heap_addrs = self.get_apr_bucket_t_addrs(proc_layer, apr_bucket_addrs)
            if not apr_bucket_heap_addrs:
                continue

            #print("apr_bucket_heap_addrs", apr_bucket_heap_addrs)

            for apr_bucket_heap_addr in apr_bucket_heap_addrs:
                gen = self.parse_apr_bucket_heap(proc_layer, task, apr_bucket_heap_addr)

                for el in gen:
                    yield el
                

    def run(self):
        # Spezifiziert die Output-Spalten
        columns = [
            ("PID", int),
            ("OFFSET (V)", format_hints.Hex),
            ("base", str),
        ]

        return renderers.TreeGrid(
            columns,
            self._generator(
                pslist.PsList.list_tasks(
                    self.context, self.config["kernel"]
                )
            ),
        )




class TLSConfig(Configuration):
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            # Specifies the OS for which the ülugin was built
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            # Specifies the dependency for the pslist-plugin
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
        ]
    
    def is_modssl_ctx_t_valid(self, proc_layer, modssl_ctx_t_addr, SSLSrvConfigRec_addr):
        sc_ptr = self.read_pointer(proc_layer, modssl_ctx_t_addr + self.modssl_ctx_t_offsets["sc_ptr"])
        if sc_ptr != SSLSrvConfigRec_addr:
            return False

        return True
    
    def is_SSLSrvConfigRec_valid(self, proc_layer, SSLSrvConfigRec_addr):
        try:
            if not SSLSrvConfigRec_addr:
                return False
            
            server_ptr = self.read_pointer(proc_layer, SSLSrvConfigRec_addr + self.SSLSrvConfigRec_offsets["server_ptr"])
            if not server_ptr:
                return False

            
            return self.is_modssl_ctx_t_valid(proc_layer, server_ptr, SSLSrvConfigRec_addr)
        
        except Exception as e: 
            print("Fehler in is_SSLSrvConfigRec_valid:", e)
            return False
    
    def is_modssl_pk_server_valid(self, proc_layer, modssl_pk_server_addr):
        try:
            cert_files_ptr = self.read_pointer(proc_layer, modssl_pk_server_addr + self.modssl_pk_server_t_offsets["cert_files_ptr"])
            cert_files = self.parse_apr_array_header_t(proc_layer, cert_files_ptr)

            key_files_ptr = self.read_pointer(proc_layer, modssl_pk_server_addr + self.modssl_pk_server_t_offsets["key_files_ptr"])
            key_files = self.parse_apr_array_header_t(proc_layer, key_files_ptr)

            return True
        except Exception as e:
            print("Fehler in is_modssl_pk_server_valid:", e)
            return False

    
    def get_ap_conf_vector_t_addr(self, proc_layer, server_rec_addr):
        module_config_ptr = self.read_pointer(proc_layer, server_rec_addr + self.server_rec_offsets["module_config_ptr"])

        return module_config_ptr

    def get_SSLSrvConfigRec_addr(self, proc_layer, ap_conf_vector_t_addr):
        #for i in range (50):
        SSLSrvConfigRec_ptr = self.read_pointer(proc_layer, ap_conf_vector_t_addr + self.type_size["pointer"] * self.ap_conf_vector_t_element_index["SSLSrvConfigRec_ptr"])
            #print("SSLSrvConfigRec_ptr", SSLSrvConfigRec_ptr)
        if self.is_SSLSrvConfigRec_valid(proc_layer, SSLSrvConfigRec_ptr):
            return SSLSrvConfigRec_ptr
        
    def get_modssl_ctx_t_addr(self, proc_layer, SSLSrvConfigRec_addr):
        server_ptr = self.read_pointer(proc_layer, SSLSrvConfigRec_addr + self.SSLSrvConfigRec_offsets["server_ptr"])

        if self.is_modssl_ctx_t_valid(proc_layer, server_ptr, SSLSrvConfigRec_addr):
            return server_ptr
        
    def get_modssl_pk_server_t(self, proc_layer, modssl_ctx_t_addr):
        pks_ptr = self.read_pointer(proc_layer, modssl_ctx_t_addr + self.modssl_ctx_t_offsets["pks_ptr"])

        if self.is_modssl_pk_server_valid(proc_layer, pks_ptr):
            return pks_ptr
        
    

    def parse_modssl_pk_server_t(self, proc_layer, task, modssl_pk_server_addr):
        cert_files_ptr = self.read_pointer(proc_layer, modssl_pk_server_addr + self.modssl_pk_server_t_offsets["cert_files_ptr"])
        cert_files = self.parse_apr_array_header_t(proc_layer, cert_files_ptr)

        key_files_ptr = self.read_pointer(proc_layer, modssl_pk_server_addr + self.modssl_pk_server_t_offsets["key_files_ptr"])
        key_files = self.parse_apr_array_header_t(proc_layer, key_files_ptr)

        ca_name_path = self.get_pointer_and_read_string(proc_layer, modssl_pk_server_addr + self.modssl_pk_server_t_offsets["ca_name_path_ptr"])
        #print("ca_name_path", ca_name_path)

        ca_name_file = self.get_pointer_and_read_string(proc_layer, modssl_pk_server_addr + self.modssl_pk_server_t_offsets["ca_name_file_ptr"])
        #print("ca_name_file", ca_name_file)

        #print("cert_files", cert_files)
        #print("key_files", key_files)
        relevant_values = self.format_output([key_files, cert_files, ca_name_path, ca_name_file])

        yield (
                    0,
                    (
                        task.pid,
                        relevant_values[0],
                        relevant_values[1],
                        relevant_values[2],
                        relevant_values[3],
                    ),
                )





    def _generator(self, tasks):
        vmlinux = self.context.modules[self.config["kernel"]]
        is_32bit = not symbols.symbol_table_is_64bit(
            self.context, vmlinux.symbol_table_name
        )
        if is_32bit:
            #print("\n32 bit!")
            self.set_offsets_for_32bit()
        else:
            #print("\n64 bit!")
            self.set_offsets_for_64bit()

         # Iteriert über alle prozesse
        for task in tasks:
            task_name = utility.array_to_string(task.comm)
            if task_name not in ("apache2", "httpd"):
                continue

            proc_layer_name = task.add_process_layer()
            if not proc_layer_name:
                continue

            proc_layer = self.context.layers[proc_layer_name]

            server_rec_addrs = self._find_server_rec_addrs(proc_layer, task)
            if not server_rec_addrs:
                continue

            ap_conf_vector_t_addrs = []
            for server_rec_addr in server_rec_addrs:
                tmp = self.get_ap_conf_vector_t_addr(proc_layer, server_rec_addr)
                if not tmp:
                    continue 

                ap_conf_vector_t_addrs.append(tmp)
            
            if not ap_conf_vector_t_addrs:
                continue

            #print("ap_conf_vector_t_addrs", ap_conf_vector_t_addrs)
    
            SSLSrvConfigRec_addrs = []
            for ap_conf_vector_t_addr in ap_conf_vector_t_addrs:
                tmp = self.get_SSLSrvConfigRec_addr(proc_layer, ap_conf_vector_t_addr)
                if not tmp:
                    continue

                SSLSrvConfigRec_addrs.append(tmp)

            #print("SSLSrvConfigRec_addrs", SSLSrvConfigRec_addrs)

            if not SSLSrvConfigRec_addrs:
                continue
            
            modssl_ctx_t_addrs = []
            for SSLSrvConfigRec_addr in SSLSrvConfigRec_addrs:
                tmp = self.get_modssl_ctx_t_addr(proc_layer, SSLSrvConfigRec_addr)
                if not tmp:
                    continue

                modssl_ctx_t_addrs.append(tmp)

            if not modssl_ctx_t_addrs:
                continue

            modssl_pk_server_t_addrs = []
            for modssl_ctx_t_addr in modssl_ctx_t_addrs:
                tmp = self.get_modssl_pk_server_t(proc_layer, modssl_ctx_t_addr)
                if not tmp:
                    continue 

                modssl_pk_server_t_addrs.append(tmp)

            #print("modssl_pk_server_t_addrs", modssl_pk_server_t_addrs)

            for modssl_pk_server_t_addr in modssl_pk_server_t_addrs:
                gen = self.parse_modssl_pk_server_t(proc_layer, task, modssl_pk_server_t_addr)

                for el in gen:
                    yield el


            

    def run(self):
        # Spezifiziert die Output-Spalten
        columns = [
            ("PID", int),
            ("key_files", str),
            ("cert_files", str),
            ("ca_name_path", str),
            ("ca_name_file", str),
        ]

        return renderers.TreeGrid(
            columns,
            self._generator(
                pslist.PsList.list_tasks(
                    self.context, self.config["kernel"]
                )
            ),
        )




class TLSConnections(Configuration):
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            # Specifies the OS for which the ülugin was built
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            # Specifies the dependency for the pslist-plugin
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
            # Specifies the dependency for the yarascan-plugin
            requirements.PluginRequirement(
                name="yarascanner", plugin=yarascan.YaraScanner, version=(2, 0, 0)
            ),
        ]
    
    def is_SSLConnRec_valid(self, proc_layer, SSLConnRec_addr):
        try:
            shutdown_type = self.read_int(proc_layer, SSLConnRec_addr + self.SSLConnRec_offsets["shutdown_type"])
            if shutdown_type not in [0, 1, 2, 3]:
                return False
            
            non_ssl_request = self.read_int(proc_layer, SSLConnRec_addr + self.SSLConnRec_offsets["non_ssl_request"])
            if non_ssl_request not in [0, 1, 2, 3]:
                return False
            
            reneg_state = self.read_int(proc_layer, SSLConnRec_addr + self.SSLConnRec_offsets["reneg_state"])
            if reneg_state not in [0, 1, 2, 3]:
                return False

            return True
        except Exception as e:
            print("Fehler in is_SSLConnRec_valid:", e)
            return False

    def get_SSLConnRec_addrs(self, proc_layer, server_rec_addr):
        addr_hex_string = struct.pack(self.pack_format, server_rec_addr).hex()
        
        addr_hex_string_yara = ""
        for i in range(0, len(addr_hex_string), 2):
            addr_hex_string_yara += addr_hex_string[i:i + 2] + " "

        hex_string = f'(00 | 01 | 02 | 03) 00 00 00 (00 | 01 | 02 | 03) 00 00 00 {addr_hex_string_yara.rstrip()}'
        rule = f'rule SSLConnRec_addr {{strings: $a = {{{hex_string}}} condition: $a}}'

        SSLConnRec_rule = yara.compile(source=rule)

        potential_SSLConnRec_addrs = []
        for offset, rule_name, name, value in proc_layer.scan(
            context=self.context, scanner=yarascan.YaraScanner(rules=SSLConnRec_rule)
            ):
                start_addr = offset - self.SSLConnRec_offsets["non_ssl_request"]
                potential_SSLConnRec_addrs.append(start_addr)
     
        SSLConnRec_addrs = []
        for potential_SSLConnRec_addr in potential_SSLConnRec_addrs:
            if self.is_SSLConnRec_valid(proc_layer, potential_SSLConnRec_addr):
                SSLConnRec_addrs.append(potential_SSLConnRec_addr)

        return SSLConnRec_addrs

        
        
    def parse_SSLConnRec(self, proc_layer, task, SSLConnRec_addr):
        shutdown_type = self.read_int(proc_layer, SSLConnRec_addr + self.SSLConnRec_offsets["shutdown_type"])
        #print("shutdown_type", shutdown_type)

        cipher_suite = self.get_pointer_and_read_string(proc_layer, SSLConnRec_addr + self.SSLConnRec_offsets["cipher_suite_ptr"])
        #print("cipher_suite", cipher_suite)

        client_dn = self.get_pointer_and_read_string(proc_layer, SSLConnRec_addr + self.SSLConnRec_offsets["client_dn_ptr"])
        #print("client_dn", client_dn)

        verify_info = self.get_pointer_and_read_string(proc_layer, SSLConnRec_addr + self.SSLConnRec_offsets["verify_info_ptr"])
        #print("verify_info", verify_info)

        verify_error = self.get_pointer_and_read_string(proc_layer, SSLConnRec_addr + self.SSLConnRec_offsets["verify_error_ptr"])
        #print("verify_error", verify_error)

        relevant_values = self.format_output([shutdown_type, cipher_suite, client_dn, verify_info, verify_error])

        yield (
                    0,
                    (
                        task.pid,
                        relevant_values[0],
                        relevant_values[1],
                        relevant_values[2],
                        relevant_values[3],
                        relevant_values[4],
                    ),
                )



    def _generator(self, tasks):
        vmlinux = self.context.modules[self.config["kernel"]]
        is_32bit = not symbols.symbol_table_is_64bit(
            self.context, vmlinux.symbol_table_name
        )
        if is_32bit:
            #print("\n32 bit!")
            self.set_offsets_for_32bit()
        else:
            #print("\n64 bit!")
            self.set_offsets_for_64bit()

         # Iteriert über alle prozesse
        for task in tasks:
            task_name = utility.array_to_string(task.comm)
            if task_name not in ("apache2", "httpd"):
                continue

            proc_layer_name = task.add_process_layer()
            if not proc_layer_name:
                continue

            proc_layer = self.context.layers[proc_layer_name]

            server_rec_addrs = self._find_server_rec_addrs(proc_layer, task)
            if not server_rec_addrs:
                continue


              
            SSLConnRec_addrs = []
            for server_rec_addr in server_rec_addrs:
                SSLConnRec_addrs.append(self.get_SSLConnRec_addrs(proc_layer, server_rec_addr))

            SSLConnRec_addrs = sum(SSLConnRec_addrs, [])
            #print("SSLConnRec_addrs", SSLConnRec_addrs)

            if not SSLConnRec_addrs:
                continue

            for SSLConnRec_addr in SSLConnRec_addrs:
                gen = self.parse_SSLConnRec(proc_layer, task, SSLConnRec_addr)

                for el in gen:
                    yield el


            

    def run(self):
        # Spezifiziert die Output-Spalten
        columns = [
            ("PID", int),
            ("shutdown_type", str),
            ("cipher_suite", str),
            ("client_dn", str),
            ("verify_info", str),
            ("verify_error", str),
        ]

        return renderers.TreeGrid(
            columns,
            self._generator(
                pslist.PsList.list_tasks(
                    self.context, self.config["kernel"]
                )
            ),
        )

class ProxyConf(Requests, Connections):
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            # Specifies the OS for which the ülugin was built
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            # Specifies the dependency for the pslist-plugin
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
            # Specifies the dependency for the yarascan-plugin
            requirements.PluginRequirement(
                name="yarascanner", plugin=yarascan.YaraScanner, version=(2, 0, 0)
            ),
        ]
    
    def is_proxy_conf_dir_valid(self, proc_layer, proxy_conf_dir_addr):
        try:
            preserve_host_set = self.read_int(proc_layer, proxy_conf_dir_addr + self.proxy_conf_dir_offsets["preserve_host_set"])
            print("preserve_host_set", preserve_host_set)
            if preserve_host_set not in (0, 1):
                return False
            error_override_set = self.read_int(proc_layer, proxy_conf_dir_addr + self.proxy_conf_dir_offsets["error_override_set"])
            print("error_override_set", error_override_set)
            if error_override_set not in (0, 1):
                return False
            alias_set = self.read_int(proc_layer, proxy_conf_dir_addr + self.proxy_conf_dir_offsets["alias_set"])
            print("alias_set", alias_set)
            if alias_set not in (0, 1):
                return False
            """
            add_forwarded_headers_set = self.read_int(proc_layer, proxy_conf_dir_addr + self.proxy_conf_dir_offsets["add_forwarded_headers_set"])
            print("add_forwarded_headers_set", add_forwarded_headers_set)
            if add_forwarded_headers_set not in (0, 1):
                return False
            forward_100_continue_set = self.read_int(proc_layer, proxy_conf_dir_addr + self.proxy_conf_dir_offsets["forward_100_continue_set"])
            print("forward_100_continue_set", forward_100_continue_set)
            if forward_100_continue_set not in (0, 1):
                return False
            async_delay_set = self.read_int(proc_layer, proxy_conf_dir_addr + self.proxy_conf_dir_offsets["async_delay_set"])
            print("async_delay_set", async_delay_set)
            if async_delay_set not in (0, 1):
                return False
            async_idle_timeout_set = self.read_int(proc_layer, proxy_conf_dir_addr + self.proxy_conf_dir_offsets["async_idle_timeout_set"])
            print("async_idle_timeout_set", async_idle_timeout_set)
            if async_idle_timeout_set not in (0, 1):
                return False
            """
            
            return True
        except:
            return False

    def get_proxy_conf_dir_addrs(self, proc_layer, task, server_rec_addrs):
        proxy_conf_dir_addrs = []
        for server_rec_addr in server_rec_addrs:
            module_config_ptr = self.read_pointer(proc_layer, server_rec_addr + self.server_rec_offsets["module_config_ptr"])
            
            #proxy_conf_dir_addr = self.read_pointer(proc_layer, module_config_ptr + 8 * 5)
            proxy_conf_dir_addr = self.read_pointer(proc_layer, module_config_ptr + self.type_size["pointer"] * 24)
           
            #print("proxy_conf_dir_addr", proxy_conf_dir_addr)

            if proxy_conf_dir_addr:
                #print("valid?", self.is_proxy_conf_dir_valid(proc_layer, proxy_conf_dir_addr))
                proxy_conf_dir_addrs.append(proxy_conf_dir_addr)

        proxy_conf_dir_addrs = list(set(proxy_conf_dir_addrs))
    
        return proxy_conf_dir_addrs

    def get_proxy_server_conf_addrs(self, proc_layer, task, server_rec_addrs):
        proxy_server_conf_addrs = []
        for server_rec_addr in server_rec_addrs:
            module_config_ptr = self.read_pointer(proc_layer, server_rec_addr + self.server_rec_offsets["module_config_ptr"])
            
            #proxy_server_conf_addr = self.read_pointer(proc_layer, module_config_ptr + 8 * 32)
            proxy_server_conf_addr = self.read_pointer(proc_layer, module_config_ptr + self.type_size["pointer"] * self.ap_conf_vector_t_element_index["proxy_server_conf_ptr"])
           
            

            if proxy_server_conf_addr:
                proxy_server_conf_addrs.append(proxy_server_conf_addr)

        proxy_server_conf_addrs = list(set(proxy_server_conf_addrs))
    
        return proxy_server_conf_addrs
    
    def parse_proxy_conf_dir_addr(self, proc_layer, task, proxy_conf_dir_addr):
        raliases_ptr = self.read_pointer(proc_layer, proxy_conf_dir_addr + self.proxy_conf_dir_offsets["raliases_ptr"])
        #print("raliases_ptr", raliases_ptr)
        aliases = self.parse_apr_array_header_t_aliases(proc_layer, raliases_ptr)

        alias_ptr = self.read_pointer(proc_layer, proxy_conf_dir_addr + self.proxy_conf_dir_offsets["alias_ptr"])
        if alias_ptr:
            alias = self.parse_proxy_alias(proc_layer, alias_ptr)
            if aliases:
                aliases.append(alias)
            else:
                aliases = [alias]
            
        if not aliases:
            return
        
        for real, fake in aliases:
            relevant_values = self.format_output([real, fake])
            
            yield (
                        0,
                        (
                            task.pid,
                            "ProxyPass",
                            relevant_values[0],
                            relevant_values[1],
                        ),
                    )

            
    def parse_proxy_server_conf_addr(self, proc_layer, task, proxy_server_conf_addr):
        aliases_ptr = self.read_pointer(proc_layer, proxy_server_conf_addr + self.proxy_server_conf_offsets["aliases_ptr"])
        aliases = self.parse_apr_array_header_t_aliases(proc_layer, aliases_ptr)

        #print("aliases", aliases)
        if not aliases:
            return

        for real, fake in aliases:
            relevant_values = self.format_output([real, fake])

            yield (
                        0,
                        (
                            task.pid,
                            "ProxyPassReverse",
                            relevant_values[0],
                            relevant_values[1],
                        ),
                    )

    

    def _generator(self, tasks):
        vmlinux = self.context.modules[self.config["kernel"]]
        is_32bit = not symbols.symbol_table_is_64bit(
            self.context, vmlinux.symbol_table_name
        )
        if is_32bit:
            #print("\n32 bit!")
            self.set_offsets_for_32bit()
        else:
            #print("\n64 bit!")
            self.set_offsets_for_64bit()

         # Iteriert über alle prozesse
        for task in tasks:
            task_name = utility.array_to_string(task.comm)
            if task_name not in ("apache2", "httpd"):
                continue

            proc_layer_name = task.add_process_layer()
            if not proc_layer_name:
                continue

            proc_layer = self.context.layers[proc_layer_name]

            server_rec_addrs = self._find_server_rec_addrs(proc_layer, task)

            #print("server_rec_addrs", server_rec_addrs)

            if not server_rec_addrs:
                continue

            proxy_conf_dir_addrs = self.get_proxy_conf_dir_addrs(proc_layer, task, server_rec_addrs)
            #print("\proxy_conf_dir_addrs", proxy_conf_dir_addrs)
            if proxy_conf_dir_addrs:
                for proxy_conf_dir_addr in proxy_conf_dir_addrs:
                   # print(f"proxy_conf_dir_addr {proxy_conf_dir_addr:#0x}")

                    gen = self.parse_proxy_conf_dir_addr(proc_layer, task, proxy_conf_dir_addr)

                    for el in gen:
                        yield el
            

            proxy_server_conf_addrs = self.get_proxy_server_conf_addrs(proc_layer, task, server_rec_addrs)

            #print("\nproxy_server_conf_addrs", proxy_server_conf_addrs)
            if proxy_server_conf_addrs:
                for proxy_server_conf_addr in proxy_server_conf_addrs:

                    gen = self.parse_proxy_server_conf_addr(proc_layer, task, proxy_server_conf_addr)

                    for el in gen:
                        yield el


            

    def run(self):
        # Spezifiziert die Output-Spalten
        columns = [
            ("PID", int),
            ("ProxyPass/ProxyPassReverse", str),
            ("real", str),
            ("fake", str),

        ]

        return renderers.TreeGrid(
            columns,
            self._generator(
                pslist.PsList.list_tasks(
                    self.context, self.config["kernel"]
                )
            ),
        )
    


class Test2(Requests, Connections):
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            # Specifies the OS for which the ülugin was built
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            # Specifies the dependency for the pslist-plugin
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
            # Specifies the dependency for the yarascan-plugin
            requirements.PluginRequirement(
                name="yarascanner", plugin=yarascan.YaraScanner, version=(2, 0, 0)
            ),
        ]
    
    def get_proxy_server_conf_addrs(self, proc_layer:TranslationLayerInterface, task:task_struct, apr_pool_t_addrs:List) -> List:
        """
        Findet mögliche Startadresse von process_rec Strukturen.
        Params:   apr_pool_t_addrs: Gefundene mögliche Startadressen von apr_pool_t Strukten.
        Returns:  Null, falls keine gefunden wurden.
                Liste der möglichen Startadressen der process_rec Strukturen, sonst.
        """
        # apr_pool_t_addrs enthält die Adressen, an denen ein Pointer auf die vermuteten apr_pool_t Strukturen gefunden wurden
        apr_pool_t_ptr_addrs = []
        for apr_pool_t_addr in apr_pool_t_addrs:
            for addr in proc_layer.scan(
                self.context,
                scanners.BytesScanner(struct.pack(self.pack_format, apr_pool_t_addr)),
                sections=task.get_process_memory_sections(),
            ):
                apr_pool_t_ptr_addrs.append(addr)
        
        if apr_pool_t_ptr_addrs == []:
            return
        
        print("pointer_addrs", apr_pool_t_ptr_addrs)

        for apr_pool_t_ptr_addr in apr_pool_t_ptr_addrs:
            id = self.get_pointer_and_read_string(proc_layer, apr_pool_t_ptr_addr - 8)
            domain = self.get_pointer_and_read_string(proc_layer, apr_pool_t_ptr_addr - 16)

            print("id", id)
            print("domain", domain)

    
    def find_proxy_conn_rec(self, proc_layer, task):
        server_rec_addrs = self._find_server_rec_addrs(proc_layer, task)
        if not server_rec_addrs:
            return

        #print("server_rec_addrs", server_rec_addrs)

        conn_rec_addrs = self._find_conn_rec_addrs(proc_layer, task)
        if not conn_rec_addrs:
            return
        
        #print("conn_rec_addrs", conn_rec_addrs)

        yara_search_request_rec_addrs = self.get_yara_search_request_rec_addrs(proc_layer, server_rec_addrs, conn_rec_addrs)

        print("conn_recs", conn_rec_addrs)
        print("request_recs", yara_search_request_rec_addrs)

        #for conn_rec_addr in conn_rec_addrs:
        for request_rec_addr in yara_search_request_rec_addrs:
            """
            conn_rec_addr_hex_string = struct.pack(self.pack_format, conn_rec_addr).hex()

            conn_rec_addr_hex_string_yara = ""
            for i in range(0, len(conn_rec_addr_hex_string), 2):
                conn_rec_addr_hex_string_yara += conn_rec_addr_hex_string[i:i + 2] + " "
            """
            request_rec_addr_hex_string = struct.pack(self.pack_format, request_rec_addr).hex()
            
            request_rec_addr_hex_string_yara = ""
            for i in range(0, len(request_rec_addr_hex_string), 2):
                request_rec_addr_hex_string_yara += request_rec_addr_hex_string[i:i + 2] + " "

            #hex_string = f'{conn_rec_addr_hex_string_yara.rstrip()} {request_rec_addr_hex_string_yara.rstrip()}'
            hex_string = f'{request_rec_addr_hex_string_yara.rstrip()}'
            print("hex string", hex_string)
            rule = f'rule proxy_conn_rec_Rule {{strings: $a = {{{hex_string}}} condition: $a}}'

            proxy_conn_rec_Rule = yara.compile(source=rule)

            
            for offset, rule_name, name, value in proc_layer.scan(
                context=self.context, scanner=yarascan.YaraScanner(rules=proxy_conn_rec_Rule)
                ):
                    print("hab was")
                    string_addr = offset + 24
                    name = self.parse_string(proc_layer, string_addr)
                    print("name", name)

    def find_proxy_dir_conf_addrs(self, proc_layer, task):
        apr_pool_t_addrs = self.get_apr_pool_t_addrs(proc_layer, task)

        # apr_pool_t_addrs enthält die Adressen, an denen ein Pointer auf die vermuteten apr_pool_t Strukturen gefunden wurden
        apr_pool_t_ptr_addrs = []
        for apr_pool_t_addr in apr_pool_t_addrs:
            for addr in proc_layer.scan(
                self.context,
                scanners.BytesScanner(struct.pack(self.pack_format, apr_pool_t_addr)),
                sections=task.get_process_memory_sections(),
            ):
                apr_pool_t_ptr_addrs.append(addr)
        
        if apr_pool_t_ptr_addrs == []:
            return
        
        array_header_t_start_addrs = apr_pool_t_ptr_addrs
        #print("array_header_t_start_addrs", array_header_t_start_addrs)

        validated_array_header_t_addrs = []
        # test validate apr_array_header_t
        for array_header_t_start_addr in array_header_t_start_addrs:
            elt_size = self.read_int(proc_layer, array_header_t_start_addr + 8)
            nelts = self.read_int(proc_layer, array_header_t_start_addr + 12)
            nalloc = self.read_int(proc_layer, array_header_t_start_addr + 16)
            elts_ptr = self.read_pointer(proc_layer, array_header_t_start_addr + 24)

            if not elts_ptr:
                continue

            # wenn nichts allokiert dann wahscheinlich nicht gültig
            if max(nelts, nalloc) == 0:
                continue

            # können es mehr sein?
            if max(nelts, nalloc) > 8000:
                continue

            validated_array_header_t_addrs.append(array_header_t_start_addr)

        #print("validated_array_header_t_addrs", validated_array_header_t_addrs)


        array_header_t_pointer_addrs = []
        for validated_array_header_t_addrs in validated_array_header_t_addrs:
            for addr in proc_layer.scan(
                self.context,
                scanners.BytesScanner(struct.pack(self.pack_format, validated_array_header_t_addrs)),
                sections=task.get_process_memory_sections(),
            ):
                array_header_t_pointer_addrs.append(addr)
        
        if array_header_t_pointer_addrs == []:
            return
        
        #print("array_header_t_pointer_addrs", array_header_t_pointer_addrs)

        validated = []
        for raliases_ptr_addr in array_header_t_pointer_addrs:
            tmp = self.read_pointer(proc_layer, raliases_ptr_addr)
            if not tmp:
                continue
            #print(f"raliases_ptr {tmp:#0x}")
            pool_addr = self.read_pointer(proc_layer, tmp)
            if not pool_addr:
                continue
            #print(f" -> pool_addr {pool_addr:#0x}")

            tmp = self.read_pointer(proc_layer, raliases_ptr_addr + 8)
            if not tmp:
                continue
            #print(f"cookie_paths_ptr {tmp:#0x}")
            pool_addr = self.read_pointer(proc_layer, tmp)
            if not pool_addr:
                continue
            #print(f" -> pool_addr {pool_addr:#0x}")

            tmp = self.read_pointer(proc_layer, raliases_ptr_addr + 16)
            if not tmp:
                continue
            #print(f"cookie_domains_ptr {tmp:#0x}")
            pool_addr = self.read_pointer(proc_layer, tmp)
            if not pool_addr:
                continue
            #print(f" -> pool_addr {pool_addr:#0x}")

            tmp = self.read_n_bytes(proc_layer, raliases_ptr_addr + 24, 1)
            tmp = self.read_n_bytes(proc_layer, raliases_ptr_addr + 25, 1)

            #alias_ptr
            tmp = self.read_n_bytes(proc_layer, raliases_ptr_addr + 32, 8)


            # wurde nur als 0 oder 1 gesetzt in mod_proxy.c
            error_override_set = self.read_int(proc_layer, raliases_ptr_addr + 52)

            preserve_host_set = error_override_set = self.read_int(proc_layer, raliases_ptr_addr + 48)

            alias_set = self.read_int(proc_layer, raliases_ptr_addr + 56)

            forward_100_continue_set = self.read_int(proc_layer, raliases_ptr_addr + 84)

            if not error_override_set in (0, 1):
                continue

            if not preserve_host_set in (0, 1):
                continue

            if not alias_set in (0, 1):
                continue

            if not forward_100_continue_set in (0, 1):
                continue
            print("ints", error_override_set, preserve_host_set, alias_set, forward_100_continue_set)
            validated.append(raliases_ptr_addr)

        print("validated", validated)
           

        """

        triplets = []
        for i in range(len(array_header_t_pointer_addrs)):
            for j in range(i+1, len(array_header_t_pointer_addrs)):
                for k in range(j+1, len(array_header_t_pointer_addrs)):
                    if array_header_t_pointer_addrs[j] - array_header_t_pointer_addrs[i] == array_header_t_pointer_addrs[k] - array_header_t_pointer_addrs[j] == 8:
                        triplets.append((array_header_t_pointer_addrs[i], array_header_t_pointer_addrs[j], array_header_t_pointer_addrs[k]))

        print("triplets", triplets)
        """
  
        



    
    def get_apr_pool_t_addrs2(self, proc_layer:TranslationLayerInterface, task:task_struct) -> List:
        """
        Findet mögliche Startadressen von apr_pool_t Strukten.
        Returns:  Null, falls keine gefunden wurden.
                Liste der möglichen Startadressen der apr_pool_t Strukturen, sonst.
        """
        # pconf_addrs enthält die Adressen, an denen der String 'pconf' gefunden wurde
        fake_addrs = []
        for address in proc_layer.scan(
            self.context,
            scanners.BytesScanner(b"/reverseProxy/ersterProxy"),
        ):
            fake_addrs.append(address)
        
        
        #print("fake_addrs", fake_addrs)
        if fake_addrs == []:
            return
        
        
        # pconf_pointer_addrs enthält die gefundenen Adressen der Pointer, welche auf die pconf Strings zeigen
        fake_pointer_addrs = []
        for fake_addr in fake_addrs:
            for addr in proc_layer.scan(
                self.context,
                scanners.BytesScanner(struct.pack(self.pack_format, fake_addr)),
                sections=task.get_process_memory_sections(),
            ):
                fake_pointer_addrs.append(addr)

        #print("fake_pointer_addrs", fake_pointer_addrs)
        if fake_pointer_addrs == []:
            return
        
        start_addrs1 = []
        for fake_pointer_addr in fake_pointer_addrs:
            start_addrs1.append(fake_pointer_addr - self.type_size["pointer"])

       

        real_addrs = []
        for address in proc_layer.scan(
            self.context,
            scanners.BytesScanner(b"http://backend.example.com/"),
        ):
            real_addrs.append(address)
        
        
        #print("real_addrs", real_addrs)
        if real_addrs == []:
            return
        
        # pconf_pointer_addrs enthält die gefundenen Adressen der Pointer, welche auf die pconf Strings zeigen
        real_pointer_addrs = []
        for real_addr in real_addrs:
            for addr in proc_layer.scan(
                self.context,
                scanners.BytesScanner(struct.pack(self.pack_format, real_addr)),
                sections=task.get_process_memory_sections(),
            ):
                real_pointer_addrs.append(addr)

        #print("real_pointer_addrs", real_pointer_addrs)
        if real_pointer_addrs == []:
            return
        
        start_addrs2 = real_pointer_addrs

        #print("start_addrs1", start_addrs1)
        print("start_addrs2", start_addrs2)

        common_start_adresses = [x for x in start_addrs1 if x in start_addrs2]
        print("common_start_adresses", common_start_adresses)
        for common_start_adresse in common_start_adresses:
            print(f"common_start_adresse {common_start_adresse:#0x}")

        common_start_adresse_ptrs = []
        for common_start_adress in common_start_adresses:
            for addr in proc_layer.scan(
                self.context,
                scanners.BytesScanner(struct.pack(self.pack_format, common_start_adress)),
                sections=task.get_process_memory_sections(),
            ):
                common_start_adresse_ptrs.append(addr)

        print("common_start_adresse_ptrs", common_start_adresse_ptrs)
        if common_start_adresse_ptrs == []:
            return

        suspected_raliases_start_addrs = []
        for common_start_adresse_ptr in common_start_adresse_ptrs:
            #nalloc = proc_layer.read(common_start_adresse_ptr - 8, 4)
            #nelts = proc_layer.read(common_start_adresse_ptr - 12, 4)
            #elt_size = proc_layer.read(common_start_adresse_ptr - 16, 4)
            #pool_ptr = proc_layer.read(common_start_adresse_ptr - 24, 8)

            """nalloc = self.read_int(proc_layer, common_start_adresse_ptr - 8)
            nelts = self.read_int(proc_layer, common_start_adresse_ptr - 12)
            elt_size = self.read_int(proc_layer, common_start_adresse_ptr - 16)
            pool_ptr = self.read_pointer(proc_layer, common_start_adresse_ptr - 24)

            print("pool_ptr", pool_ptr)
            print("elt_size", elt_size)
            print("nelts", nelts)
            print("nalloc", nalloc)"""

            start_addr = common_start_adresse_ptr - self.apr_array_header_t_offsets["elts_ptr"]

            pool_ptr = self.read_pointer(proc_layer, start_addr + self.apr_array_header_t_offsets["pool_ptr"])

            tag = self.get_pointer_and_read_string(proc_layer, pool_ptr + self.apr_pool_t_offsets["tag_ptr"])
            if tag == "pconf":
                suspected_raliases_start_addrs.append(start_addr)

            

        # Bei testfall scheinen dies alles richtige apr_array_header_t strukturen zu sein. 
        # An der stelle für den pool pointer liegt tatsächlich ein pointer zu einem pool mit tag "pconf"

        raliases_ptr_addrs = []
        for suspected_raliases_start_addr in suspected_raliases_start_addrs:
            for addr in proc_layer.scan(
                self.context,
                scanners.BytesScanner(struct.pack(self.pack_format, suspected_raliases_start_addr)),
                sections=task.get_process_memory_sections(),
            ):
                raliases_ptr_addrs.append(addr)

        print("raliases_ptr_addrs", raliases_ptr_addrs)

        proxy_dir_conf_addrs = []

        for raliases_ptr_addr in raliases_ptr_addrs:
            tmp = self.read_pointer(proc_layer, raliases_ptr_addr)
            print(f"raliases_ptr {tmp:#0x}")
            pool_addr = self.read_pointer(proc_layer, tmp)
            print(f" -> pool_addr {pool_addr:#0x}")

            tmp = self.read_pointer(proc_layer, raliases_ptr_addr + self.type_size["pointer"])
            print(f"cookie_paths_ptr {tmp:#0x}")
            pool_addr = self.read_pointer(proc_layer, tmp)
            print(f" -> pool_addr {pool_addr:#0x}")

            tmp = self.read_pointer(proc_layer, raliases_ptr_addr + 2*self.type_size["pointer"])
            #print(f"cookie_domains_ptr {tmp:#0x}")
            pool_addr = self.read_pointer(proc_layer, tmp)
            #print(f" -> pool_addr {pool_addr:#0x}")

            tmp = self.read_n_bytes(proc_layer, raliases_ptr_addr +  3*self.type_size["pointer"], 1)
            tmp = self.read_n_bytes(proc_layer, raliases_ptr_addr + 3*self.type_size["pointer"] + 1, 1)

            #alias_ptr
            tmp = self.read_n_bytes(proc_layer, raliases_ptr_addr + 4*self.type_size["pointer"], 8)


            # wurde nur als 0 oder 1 gesetzt in mod_proxy.c
            error_override_set = self.read_int(proc_layer, raliases_ptr_addr + 52)

            preserve_host_set = error_override_set = self.read_int(proc_layer, raliases_ptr_addr + 48)

            alias_set = self.read_int(proc_layer, raliases_ptr_addr + 56)

            forward_100_continue_set = self.read_int(proc_layer, raliases_ptr_addr + 84)

            print("ints", error_override_set, preserve_host_set, alias_set, forward_100_continue_set)
            #tmp = self.read_n_bytes(proc_layer, raliases_ptr_addr + 40, 7*4)

            proxy_dir_conf_addrs.append(raliases_ptr_addr - 2*self.type_size["pointer"])

        #print("proxy_dir_conf_addrs", proxy_dir_conf_addrs)

        server_rec_addrs = self._find_server_rec_addrs(proc_layer, task)

        print("server_rec_addrs", server_rec_addrs)
        print()
        proxy_dir_ptr_addrs = []
        for proxy_dir_conf_addr in proxy_dir_conf_addrs:
            for addr in proc_layer.scan(
                self.context,
                scanners.BytesScanner(struct.pack(self.pack_format, proxy_dir_conf_addr)),
                sections=task.get_process_memory_sections(),
            ):
                proxy_dir_ptr_addrs.append(addr)
                print(f"proxy_dir_ptr_addr {addr:#0x}")



        for server_rec_addr in server_rec_addrs:
            module_config_ptr = self.read_pointer(proc_layer, server_rec_addr + self.server_rec_offsets["module_config_ptr"])
            for proxy_dir_ptr_addr in proxy_dir_ptr_addrs:
                diff = proxy_dir_ptr_addr - module_config_ptr
                index = diff / self.type_size["pointer"]
                print(f"module_config_ptr {module_config_ptr:#0x}, proxy_dir_ptr_addr {proxy_dir_ptr_addr:#0x}, diff {diff} Bytes, index {index}")

    

    def get_apr_pool_t_addrs3(self, proc_layer:TranslationLayerInterface, task:task_struct) -> List:
        """
        Findet mögliche Startadressen von apr_pool_t Strukten.
        Returns:  Null, falls keine gefunden wurden.
                Liste der möglichen Startadressen der apr_pool_t Strukturen, sonst.
        """
        # pconf_addrs enthält die Adressen, an denen der String 'pconf' gefunden wurde
        fake_addrs = []
        for address in proc_layer.scan(
            self.context,
            scanners.BytesScanner(b"/fakeP1"),
        ):
            fake_addrs.append(address)
        
        
        #print("fake_addrs", fake_addrs)
        if fake_addrs == []:
            return
        
        
        # pconf_pointer_addrs enthält die gefundenen Adressen der Pointer, welche auf die pconf Strings zeigen
        fake_pointer_addrs = []
        for fake_addr in fake_addrs:
            for addr in proc_layer.scan(
                self.context,
                scanners.BytesScanner(struct.pack(self.pack_format, fake_addr)),
                sections=task.get_process_memory_sections(),
            ):
                fake_pointer_addrs.append(addr)

        #print("fake_pointer_addrs", fake_pointer_addrs)
        if fake_pointer_addrs == []:
            return
        
        start_addrs1 = []
        for fake_pointer_addr in fake_pointer_addrs:
            start_addrs1.append(fake_pointer_addr - 8)

       

        real_addrs = []
        for address in proc_layer.scan(
            self.context,
            scanners.BytesScanner(b"http://127.0.0.1:10000/"),
        ):
            real_addrs.append(address)
        
        
        #print("real_addrs", real_addrs)
        if real_addrs == []:
            return
        
        # pconf_pointer_addrs enthält die gefundenen Adressen der Pointer, welche auf die pconf Strings zeigen
        real_pointer_addrs = []
        for real_addr in real_addrs:
            for addr in proc_layer.scan(
                self.context,
                scanners.BytesScanner(struct.pack(self.pack_format, real_addr)),
                sections=task.get_process_memory_sections(),
            ):
                real_pointer_addrs.append(addr)

        #print("real_pointer_addrs", real_pointer_addrs)
        if real_pointer_addrs == []:
            return
        
        start_addrs2 = real_pointer_addrs

        #print("start_addrs1", start_addrs1)
        #print("start_addrs2", start_addrs2)

        common_start_adresses = [x for x in start_addrs1 if x in start_addrs2]
        print("common_start_adresses", common_start_adresses)
        for common_start_adresse in common_start_adresses:
            print(f"common_start_adresse {common_start_adresse:#0x}")

        common_start_adresse_ptrs = []
        for common_start_adress in common_start_adresses:
            for addr in proc_layer.scan(
                self.context,
                scanners.BytesScanner(struct.pack(self.pack_format, common_start_adress)),
                sections=task.get_process_memory_sections(),
            ):
                common_start_adresse_ptrs.append(addr)

        print("common_start_adresse_ptrs", common_start_adresse_ptrs)
        if common_start_adresse_ptrs == []:
            return

        suspected_raliases_start_addrs = []
        for common_start_adresse_ptr in common_start_adresse_ptrs:
            #nalloc = proc_layer.read(common_start_adresse_ptr - 8, 4)
            #nelts = proc_layer.read(common_start_adresse_ptr - 12, 4)
            #elt_size = proc_layer.read(common_start_adresse_ptr - 16, 4)
            #pool_ptr = proc_layer.read(common_start_adresse_ptr - 24, 8)

            nalloc = self.read_int(proc_layer, common_start_adresse_ptr - 8)
            nelts = self.read_int(proc_layer, common_start_adresse_ptr - 12)
            elt_size = self.read_int(proc_layer, common_start_adresse_ptr - 16)
            pool_ptr = self.read_pointer(proc_layer, common_start_adresse_ptr - 24)

            print("pool_ptr", pool_ptr)
            print("elt_size", elt_size)
            print("nelts", nelts)
            print("nalloc", nalloc)

            tag = self.get_pointer_and_read_string(proc_layer, pool_ptr + self.apr_pool_t_offsets["tag_ptr"])
            if tag == "pconf":
                suspected_raliases_start_addrs.append(common_start_adresse_ptr - 24)

        # Bei testfall scheinen dies alles richtige apr_array_header_t strukturen zu sein. 
        # An der stelle für den pool pointer liegt tatsächlich ein pointer zu einem pool mit tag "pconf"

        raliases_ptr_addrs = []
        for suspected_raliases_start_addr in suspected_raliases_start_addrs:
            for addr in proc_layer.scan(
                self.context,
                scanners.BytesScanner(struct.pack(self.pack_format, suspected_raliases_start_addr)),
                sections=task.get_process_memory_sections(),
            ):
                raliases_ptr_addrs.append(addr)

        print("raliases_ptr_addrs", raliases_ptr_addrs)

        proxy_dir_conf_addrs = []

        for raliases_ptr_addr in raliases_ptr_addrs:
            tmp = self.read_pointer(proc_layer, raliases_ptr_addr)
            print(f"raliases_ptr {tmp:#0x}")
            pool_addr = self.read_pointer(proc_layer, tmp)
            print(f" -> pool_addr {pool_addr:#0x}")

            tmp = self.read_pointer(proc_layer, raliases_ptr_addr + 8)
            print(f"cookie_paths_ptr {tmp:#0x}")
            pool_addr = self.read_pointer(proc_layer, tmp)
            print(f" -> pool_addr {pool_addr:#0x}")

            tmp = self.read_pointer(proc_layer, raliases_ptr_addr + 16)
            print(f"cookie_domains_ptr {tmp:#0x}")
            pool_addr = self.read_pointer(proc_layer, tmp)
            print(f" -> pool_addr {pool_addr:#0x}")

            tmp = self.read_n_bytes(proc_layer, raliases_ptr_addr + 24, 1)
            tmp = self.read_n_bytes(proc_layer, raliases_ptr_addr + 25, 1)

            #alias_ptr
            tmp = self.read_n_bytes(proc_layer, raliases_ptr_addr + 32, 8)


            # wurde nur als 0 oder 1 gesetzt in mod_proxy.c
            error_override_set = self.read_int(proc_layer, raliases_ptr_addr + 52)

            preserve_host_set = error_override_set = self.read_int(proc_layer, raliases_ptr_addr + 48)

            alias_set = self.read_int(proc_layer, raliases_ptr_addr + 56)

            forward_100_continue_set = self.read_int(proc_layer, raliases_ptr_addr + 84)

            print("ints", error_override_set, preserve_host_set, alias_set, forward_100_continue_set)
            #tmp = self.read_n_bytes(proc_layer, raliases_ptr_addr + 40, 7*4)

            proxy_dir_conf_addrs.append(raliases_ptr_addr - 16)

        #print("proxy_dir_conf_addrs", proxy_dir_conf_addrs)

        server_rec_addrs = self._find_server_rec_addrs(proc_layer, task)

        print("server_rec_addrs", server_rec_addrs)
        print()
        proxy_dir_ptr_addrs = []
        for proxy_dir_conf_addr in proxy_dir_conf_addrs:
            for addr in proc_layer.scan(
                self.context,
                scanners.BytesScanner(struct.pack(self.pack_format, proxy_dir_conf_addr)),
                sections=task.get_process_memory_sections(),
            ):
                proxy_dir_ptr_addrs.append(addr)
                print(f"proxy_dir_ptr_addr {addr:#0x}")



        for server_rec_addr in server_rec_addrs:
            module_config_ptr = self.read_pointer(proc_layer, server_rec_addr + self.server_rec_offsets["module_config_ptr"])
            for proxy_dir_ptr_addr in proxy_dir_ptr_addrs:
                diff = proxy_dir_ptr_addr - server_rec_addr
                print(f"module_config_ptr {module_config_ptr:#0x},proxy_dir_ptr_addr {proxy_dir_ptr_addr:#0x}, diff {diff/8}")



    def get_proxy_conf_dir_addrs(self, proc_layer, task):
        server_rec_addrs = self._find_server_rec_addrs(proc_layer, task)

        proxy_conf_dir_addrs = []
        for server_rec_addr in server_rec_addrs:
            module_config_ptr = self.read_pointer(proc_layer, server_rec_addr + self.server_rec_offsets["module_config_ptr"])

            proxy_conf_dir_addr = self.read_pointer(proc_layer, module_config_ptr + 8 * 89)

            if proxy_conf_dir_addr:
                proxy_conf_dir_addrs.append(proxy_conf_dir_addr)

        proxy_conf_dir_addrs = list(set(proxy_conf_dir_addrs))
        print("proxy_conf_dir_addrs", proxy_conf_dir_addrs)

        return proxy_conf_dir_addrs

        

    def tmp2(self, proc_layer):
        hex_string = f'(00 | 01 | 02) 00 00 00 (00 | 01 | 02 | 03) 00 00 00 [8] [8] [8] [8] 01 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00'
        rule = f'rule SSLConnRec_addr {{strings: $a = {{{hex_string}}} condition: $a}}'

        session_rec_rule = yara.compile(source=rule)

        potential_session_rec_addrs = []
        for offset, rule_name, name, value in proc_layer.scan(
            context=self.context, scanner=yarascan.YaraScanner(rules=session_rec_rule)
            ):
                print("mmmmmm")

    def tmp(self, proc_layer, server_rec_addr):
        module_config_ptr = self.read_pointer(proc_layer, server_rec_addr + self.server_rec_offsets["module_config_ptr"])

        a = {"req" : 96}

        # ca 188
        print()
        num_of_modules = 0
        tmp = proc_layer.read(module_config_ptr, 8*50)
        for i in range(55):
            tmp = self.read_pointer(proc_layer, module_config_ptr + 8*i)
            if not tmp:
                continue
            num_of_modules += 1
            print(f"pos {i}: {tmp:#0x}")


            # 72 80

            #print("domain", self.get_pointer_and_read_string(proc_layer, tmp + 72))
            #print("id", self.get_pointer_and_read_string(proc_layer, tmp + 80))

            

            #tmp = proc_layer.read(tmp, 250)
            #print("tmp", tmp)
        print("Anzahl Module", num_of_modules)
        #core_server_config_ptr = self.read_pointer(proc_layer, module_config_ptr + self.type_size["pointer"] * self.ap_conf_vector_t_element_index["core_server_config_ptr"])

    
    



    def _generator(self, tasks):
        vmlinux = self.context.modules[self.config["kernel"]]
        is_32bit = not symbols.symbol_table_is_64bit(
            self.context, vmlinux.symbol_table_name
        )
        if is_32bit:
            #print("\n32 bit!")
            self.set_offsets_for_32bit()
        else:
            #print("\n64 bit!")
            self.set_offsets_for_64bit()

         # Iteriert über alle prozesse
        for task in tasks:
            task_name = utility.array_to_string(task.comm)
            if task_name not in ("apache2", "httpd"):
                continue

            proc_layer_name = task.add_process_layer()
            if not proc_layer_name:
                continue

            proc_layer = self.context.layers[proc_layer_name]

            """
            server_rec_addrs = self._find_server_rec_addrs(proc_layer, task)
            print("server_rec_addrs", server_rec_addrs)
            if not server_rec_addrs:
                continue

            for server_rec_addr in server_rec_addrs:
                #self.tmp(proc_layer, server_rec_addr)
                self.tmp2(proc_layer)
            """

            #self.get_proxy_conf_dir_addrs(proc_layer, task)


            #tag = self.get_pointer_and_read_string(proc_layer, 93931734700936 + self.apr_pool_t_offsets["tag_ptr"])
            #print("tag", tag)

            #apr_pool_t_addrs = self.get_apr_pool_t_addrs3(proc_layer, task)

            #self.find_proxy_dir_conf_addrs(proc_layer, task)
            self.get_apr_pool_t_addrs2(proc_layer, task)
            #if not apr_pool_t_addrs:
            #    continue
            #print("aaaaa")
            #self.find_proxy_conn_rec(proc_layer, task)
            #self.get_proxy_server_conf_addrs(proc_layer, task, apr_pool_t_addrs)


            

            


            

    def run(self):
        # Spezifiziert die Output-Spalten
        columns = [
            ("PID", int),
            ("shutdown_type", str),
            ("cipher_suite", str),
            ("client_dn", str),
            ("verify_info", str),
            ("verify_error", str),
        ]

        return renderers.TreeGrid(
            columns,
            self._generator(
                pslist.PsList.list_tasks(
                    self.context, self.config["kernel"]
                )
            ),
        )


class Test(Configuration):
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            # Specifies the OS for which the ülugin was built
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            # Specifies the dependency for the pslist-plugin
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
            # Specifies the dependency for the yarascan-plugin
            requirements.PluginRequirement(
                name="yarascanner", plugin=yarascan.YaraScanner, version=(2, 0, 0)
            ),
        ]
    
    def get_session_rec_addrs(self, proc_layer):
        hex_string = f'(00 | 01) 00 00 00 (00 | 01) 00 00 00 (00 | 01) 00 00 00 '
        rule = f'rule SSLConnRec_addr {{strings: $a = {{{hex_string}}} condition: $a}}'

        session_rec_rule = yara.compile(source=rule)

        potential_session_rec_addrs = []
        for offset, rule_name, name, value in proc_layer.scan(
            context=self.context, scanner=yarascan.YaraScanner(rules=session_rec_rule)
            ):
                start_addr = offset - self.SSLConnRec_offsets["non_ssl_request"]
                potential_session_rec_addrs.append(start_addr)
     
        session_rec_addrs = []
        for potential_session_rec_addr in potential_session_rec_addrs:
            print(potential_session_rec_addr)

        return session_rec_addrs
    
    session_rec_offsets = {
        "pool_ptr":0,
        "uuid_ptr":8,
        "remote_user_ptr":16,
        "entries_ptr":24,
        "encoded_ptr": 32,
        "expiry": 40,
        "maxage": 48,
        "dirty" : 56,
        "cached": 60,
        "written": 64,

    }
    

    def is_session_rec_valid(self, proc_layer:TranslationLayerInterface, session_rec_addr:int) -> bool:
        """
        Validiert potenzielle process_rec Adressen.
        Params:   process_rec_addr -> potenzielle Startadresse für ein process_rec.
        Returns:  True, wenn es sich wahrscheinlich um ein process_rec handelt.
                False, sonst.
        """
        try:
            tmp = proc_layer.read(session_rec_addr, 68)

            dirty = self.read_n_bytes(proc_layer, session_rec_addr + self.session_rec_offsets["dirty"], 4)
            cached = self.read_n_bytes(proc_layer, session_rec_addr + self.session_rec_offsets["cached"], 4)
            written = self.read_n_bytes(proc_layer, session_rec_addr + self.session_rec_offsets["written"], 4)

            entries_ptr = self.read_pointer(proc_layer, session_rec_addr + self.session_rec_offsets["entries_ptr"])

            

            if not written in (0, 1):
                return False
            
            if not cached in (0, 1):
                return False
            
            if not entries_ptr:
                return False
            
            remote_user_ptr = self.read_pointer(proc_layer, session_rec_addr + self.session_rec_offsets["remote_user_ptr"])

            if not remote_user_ptr:
                return False
            
            remote_user = self.parse_string(proc_layer, remote_user_ptr)

            if not remote_user:
                return False

            print(remote_user)
            
            tmp_ptr = self.read_pointer(proc_layer, entries_ptr)
            
            """outp = self.parse_apr_array_header_t(proc_layer, tmp_ptr)

            if not outp:
                return False

            print(outp)
            """

            expiry = self.read_n_bytes(proc_layer, session_rec_addr + self.session_rec_offsets["expiry"], 8)
            expiry_readable = datetime.datetime.utcfromtimestamp(expiry / 1000000).strftime("%Y-%m-%d %H:%M:%S")

            if "197" in expiry_readable:
                return False

            print("expiry_readable", expiry_readable)
      
            
            print("entries_ptr", entries_ptr)
            print("dirty", dirty, "cached", cached, "written", written)
            
            return True
        except Exception as e: 
            print("Fehler in is_process_rec_valid:", e)
            return False
        

    
    def get_apr_pool_t_addrs(self, proc_layer:TranslationLayerInterface, task:task_struct) -> List:
        """
        Findet mögliche Startadressen von apr_pool_t Strukten.
        Returns:  Null, falls keine gefunden wurden.
                Liste der möglichen Startadressen der apr_pool_t Strukturen, sonst.
        """
        # pconf_addrs enthält die Adressen, an denen der String 'pconf' gefunden wurde
        pconf_addrs = []
        for address in proc_layer.scan(
            self.context,
            scanners.BytesScanner(b"h2_session"),
            sections=task.get_process_memory_sections(),
        ):
            pconf_addrs.append(address)
        
        
        #print("pconf_addrs", pconf_addrs)
        if pconf_addrs == []:
            return
        
        # pconf_pointer_addrs enthält die gefundenen Adressen der Pointer, welche auf die pconf Strings zeigen
        pconf_pointer_addrs = []
        for pconf_addr in pconf_addrs:
            for addr in proc_layer.scan(
                self.context,
                scanners.BytesScanner(struct.pack(self.pack_format, pconf_addr)),
                sections=task.get_process_memory_sections(),
            ):
                pconf_pointer_addrs.append(addr)

        #print("pconf_pointer_addrs", pconf_pointer_addrs)
        if pconf_pointer_addrs == []:
            return

        # apr_pool_t_addrs enthält die Startadressen von den vermuteten apr_pool_t_addrs Structs.
        apr_pool_t_addrs = []
        for pconf_pointer_addr in pconf_pointer_addrs:
            apr_pool_t_addrs.append(pconf_pointer_addr - self.apr_pool_t_offsets["tag_ptr"])

        return apr_pool_t_addrs
    
    def tmp(self, proc_layer:TranslationLayerInterface, task:task_struct) -> List:
        """
        Findet mögliche Startadressen von apr_pool_t Strukten.
        Returns:  Null, falls keine gefunden wurden.
                Liste der möglichen Startadressen der apr_pool_t Strukturen, sonst.
        """
        # pconf_addrs enthält die Adressen, an denen der String 'pconf' gefunden wurde
        pconf_addrs = []
        for address in proc_layer.scan(
            self.context,
            scanners.BytesScanner(b'TestUserABC'),
            sections=task.get_process_memory_sections(),
        ):
            pconf_addrs.append(address)
        
        
        
        if pconf_addrs == []:
            return
        
        print("TestUserABC addrs", pconf_addrs)

        for pconf_addr in pconf_addrs:
            tmp = proc_layer.read(pconf_addr - 50, 150)
            print(tmp)

        
        
        # pconf_pointer_addrs enthält die gefundenen Adressen der Pointer, welche auf die pconf Strings zeigen
        pconf_pointer_addrs = []
        for pconf_addr in pconf_addrs:
            for addr in proc_layer.scan(
                self.context,
                scanners.BytesScanner(struct.pack(self.pack_format, pconf_addr)),
                sections=task.get_process_memory_sections(),
            ):
                pconf_pointer_addrs.append(addr)

        print("test_user_ptr_adresses", pconf_pointer_addrs)
        
        for pconf_pointer_addr in pconf_pointer_addrs:
            start_addr = pconf_pointer_addr - 16
            print("start_addr", start_addr)

            uuid_ptr = self.read_pointer(proc_layer, start_addr + 8)
            try:
                uuid = proc_layer.read(uuid_ptr, 18)
                print("uuid", uuid)
            except:
                0

            pool_addr = self.read_pointer(proc_layer, start_addr)
            tag = self.get_pointer_and_read_string(proc_layer, pool_addr + self.apr_pool_t_offsets["tag_ptr"])
            print("tag", tag)

    
    def get_session_rec_addrs(self, proc_layer:TranslationLayerInterface, task:task_struct, apr_pool_t_addrs:List) -> List:
        """
        Findet mögliche Startadresse von process_rec Strukturen.
        Params:   apr_pool_t_addrs: Gefundene mögliche Startadressen von apr_pool_t Strukten.
        Returns:  Null, falls keine gefunden wurden.
                Liste der möglichen Startadressen der process_rec Strukturen, sonst.
        """

        # apr_pool_t_addrs enthält die Adressen, an denen ein Pointer auf die vermuteten apr_pool_t Strukturen gefunden wurden
        apr_pool_t_ptr_addrs = []
        for apr_pool_t_addr in apr_pool_t_addrs:
            for addr in proc_layer.scan(
                self.context,
                scanners.BytesScanner(struct.pack(self.pack_format, apr_pool_t_addr)),
                sections=task.get_process_memory_sections(),
            ):
                apr_pool_t_ptr_addrs.append(addr)
        
        if apr_pool_t_ptr_addrs == []:
            return

        print("apr_pool_t_ptr_addrs", apr_pool_t_ptr_addrs)
         # potential_process_rec_addrs enthält die potenziellen Startadressen der process_rec Strukturen.
        potential_session_rec_addrs = []
        for apr_pool_t_ptr_addr in apr_pool_t_ptr_addrs:
            potential_session_rec_addrs.append(apr_pool_t_ptr_addr)
        
        # process_rec_addrs enthält die nach einer validierung übrig gebliebenen Startadressen auf die process_rec Strukturen
        session_rec_addrs = []
        for potential_session_rec_addr in potential_session_rec_addrs:
            if(self.is_session_rec_valid(proc_layer, potential_session_rec_addr)):
                session_rec_addrs.append(potential_session_rec_addr)

        if session_rec_addrs == []:
            return
        
        print("session_rec_addrs", session_rec_addrs)

        return session_rec_addrs

        
        




    def _generator(self, tasks):
        vmlinux = self.context.modules[self.config["kernel"]]
        is_32bit = not symbols.symbol_table_is_64bit(
            self.context, vmlinux.symbol_table_name
        )
        if is_32bit:
            #print("\n32 bit!")
            self.set_offsets_for_32bit()
        else:
            #print("\n64 bit!")
            self.set_offsets_for_64bit()

         # Iteriert über alle prozesse
        for task in tasks:
            task_name = utility.array_to_string(task.comm)
            if task_name not in ("apache2", "httpd"):
                continue

            proc_layer_name = task.add_process_layer()
            if not proc_layer_name:
                continue

            proc_layer = self.context.layers[proc_layer_name]

            self.tmp(proc_layer, task)

            """addrs = self.get_apr_pool_t_addrs(proc_layer, task)

            if not addrs:
                continue

            self.get_session_rec_addrs(proc_layer, task, addrs)"""

            #print(addrs)

            


            

    def run(self):
        # Spezifiziert die Output-Spalten
        columns = [
            ("PID", int),
            ("shutdown_type", str),
            ("cipher_suite", str),
            ("client_dn", str),
            ("verify_info", str),
            ("verify_error", str),
        ]

        return renderers.TreeGrid(
            columns,
            self._generator(
                pslist.PsList.list_tasks(
                    self.context, self.config["kernel"]
                )
            ),
        )