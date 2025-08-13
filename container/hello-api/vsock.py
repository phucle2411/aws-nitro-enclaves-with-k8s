#!/usr/bin/env python3
# vsock-bidirectional-proxy.py

import socket
import sys
import threading
import json
import subprocess
import argparse
import logging
from enum import Enum

class ProxyMode(Enum):
    TCP_TO_VSOCK = "tcp-to-vsock"  # Ingress: External -> Enclave
    VSOCK_TO_TCP = "vsock-to-tcp"  # Egress: Enclave -> External

class VSockProxy:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.active_connections = []
        self.running = True
        
    def get_enclave_cid(self):
        """Get the CID of the running enclave"""
        try:
            result = subprocess.run(['nitro-cli', 'describe-enclaves'], 
                                  capture_output=True, text=True)
            enclaves = json.loads(result.stdout)
            if enclaves:
                return enclaves[0]['EnclaveCID']
        except Exception as e:
            self.logger.error(f"Failed to get enclave CID: {e}")
        return None

    def forward_data(self, src, dst, connection_name):
        """Forward data between sockets"""
        try:
            while self.running:
                data = src.recv(4096)
                if not data:
                    break
                dst.sendall(data)
        except Exception as e:
            self.logger.debug(f"Forward ended for {connection_name}: {e}")
        finally:
            try:
                src.shutdown(socket.SHUT_RDWR)
                dst.shutdown(socket.SHUT_RDWR)
            except:
                pass
            src.close()
            dst.close()

    def handle_tcp_to_vsock(self, tcp_client, addr, vsock_cid, vsock_port):
        """Handle incoming TCP connection and forward to VSOCK"""
        connection_name = f"TCP:{addr} -> VSOCK:{vsock_cid}:{vsock_port}"
        self.logger.info(f"New connection: {connection_name}")
        
        try:
            # Connect to VSOCK
            vsock_sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
            vsock_sock.connect((vsock_cid, vsock_port))
            
            # Create bidirectional forwarding
            t1 = threading.Thread(target=self.forward_data, 
                                args=(tcp_client, vsock_sock, f"{connection_name} (TCP->VSOCK)"))
            t2 = threading.Thread(target=self.forward_data, 
                                args=(vsock_sock, tcp_client, f"{connection_name} (VSOCK->TCP)"))
            
            t1.start()
            t2.start()
            
            self.active_connections.append((t1, t2))
            
        except Exception as e:
            self.logger.error(f"Failed to handle {connection_name}: {e}")
            tcp_client.close()

    def handle_vsock_to_tcp(self, vsock_client, addr, tcp_host, tcp_port):
        """Handle incoming VSOCK connection and forward to TCP"""
        connection_name = f"VSOCK:{addr} -> TCP:{tcp_host}:{tcp_port}"
        self.logger.info(f"New connection: {connection_name}")
        
        try:
            # Connect to TCP endpoint
            tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp_sock.connect((tcp_host, tcp_port))
            
            # Create bidirectional forwarding
            t1 = threading.Thread(target=self.forward_data, 
                                args=(vsock_client, tcp_sock, f"{connection_name} (VSOCK->TCP)"))
            t2 = threading.Thread(target=self.forward_data, 
                                args=(tcp_sock, vsock_client, f"{connection_name} (TCP->VSOCK)"))
            
            t1.start()
            t2.start()
            
            self.active_connections.append((t1, t2))
            
        except Exception as e:
            self.logger.error(f"Failed to handle {connection_name}: {e}")
            vsock_client.close()

    def run_tcp_to_vsock(self, tcp_port, vsock_cid, vsock_port):
        """Run TCP to VSOCK proxy (ingress)"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', tcp_port))
        server.listen(5)
        
        self.logger.info(f"TCP to VSOCK proxy: 0.0.0.0:{tcp_port} -> CID:{vsock_cid}:{vsock_port}")
        
        try:
            while self.running:
                client, addr = server.accept()
                threading.Thread(target=self.handle_tcp_to_vsock,
                               args=(client, addr, vsock_cid, vsock_port)).start()
        except KeyboardInterrupt:
            self.logger.info("Shutting down TCP to VSOCK proxy...")
        finally:
            server.close()

    def run_vsock_to_tcp(self, vsock_port, tcp_host, tcp_port):
        """Run VSOCK to TCP proxy (egress)"""
        server = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        server.bind((socket.VMADDR_CID_ANY, vsock_port))
        server.listen(5)
        
        self.logger.info(f"VSOCK to TCP proxy: VSOCK:{vsock_port} -> {tcp_host}:{tcp_port}")
        
        try:
            while self.running:
                client, addr = server.accept()
                threading.Thread(target=self.handle_vsock_to_tcp,
                               args=(client, addr, tcp_host, tcp_port)).start()
        except KeyboardInterrupt:
            self.logger.info("Shutting down VSOCK to TCP proxy...")
        finally:
            server.close()

    def shutdown(self):
        """Shutdown all proxy connections"""
        self.running = False
        for t1, t2 in self.active_connections:
            t1.join(timeout=1)
            t2.join(timeout=1)

def main():
    parser = argparse.ArgumentParser(description='Bidirectional VSOCK Proxy')
    parser.add_argument('mode', choices=['tcp-to-vsock', 'vsock-to-tcp', 'both'],
                       help='Proxy mode')
    parser.add_argument('--tcp-port', type=int, help='TCP port to listen on or connect to')
    parser.add_argument('--vsock-port', type=int, help='VSOCK port to listen on or connect to')
    parser.add_argument('--vsock-cid', type=int, help='VSOCK CID (auto-detect if not specified)')
    parser.add_argument('--tcp-host', default='localhost', help='TCP host to connect to (for vsock-to-tcp)')
    parser.add_argument('--config', help='JSON config file for multiple proxies')
    parser.add_argument('--log-level', default='INFO', help='Logging level')
    
    args = parser.parse_args()
    
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    proxy = VSockProxy()
    
    if args.config:
        # Load configuration for multiple proxies
        with open(args.config, 'r') as f:
            config = json.load(f)
        
        threads = []
        
        # Start ingress proxies (TCP to VSOCK)
        for ingress in config.get('ingress', []):
            vsock_cid = ingress.get('vsock_cid') or proxy.get_enclave_cid()
            t = threading.Thread(target=proxy.run_tcp_to_vsock,
                               args=(ingress['tcp_port'], vsock_cid, ingress['vsock_port']))
            t.start()
            threads.append(t)
        
        # Start egress proxies (VSOCK to TCP)
        for egress in config.get('egress', []):
            t = threading.Thread(target=proxy.run_vsock_to_tcp,
                               args=(egress['vsock_port'], egress['tcp_host'], egress['tcp_port']))
            t.start()
            threads.append(t)
        
        # Wait for all threads
        try:
            for t in threads:
                t.join()
        except KeyboardInterrupt:
            proxy.shutdown()
            
    else:
        # Single proxy mode
        if args.mode == 'tcp-to-vsock':
            vsock_cid = args.vsock_cid or proxy.get_enclave_cid()
            if not vsock_cid:
                print("Error: Could not determine enclave CID")
                sys.exit(1)
            proxy.run_tcp_to_vsock(args.tcp_port, vsock_cid, args.vsock_port)
            
        elif args.mode == 'vsock-to-tcp':
            proxy.run_vsock_to_tcp(args.vsock_port, args.tcp_host, args.tcp_port)

if __name__ == "__main__":
    main()