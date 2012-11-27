#coding = utf-8
#coding=utf-8
import os,sys
from ctypes import *
import subprocess

class VirusScanner():
    def __init__( self, name, cmdline, flush_method ):
    	self.name = name
    	self.cmdline = cmdline.split()
        print self.cmdline
    	self.process = subprocess.Popen(cmdline, stdout = subprocess.PIPE)
        
        #print vixfile
        self.dll = cdll.LoadLibrary( "avctrl.dll" )
        self.AtachScanner = self.dll.AtachScanner
        self.AtachScanner.restype = c_int
        self.ScanFile = self.dll.ScanFile
        self.ScanFile.restype = c_int
        self.WaitScannerReady = self.dll.WaitScannerReady
        self.WaitScannerReady.restype = c_int

        #注入到扫描器进程中
        self.scanner = self.AtachScanner(self.process.pid, flush_method)
        #让扫描器开始工作，
        self.process.send_signal()
        #等待扫描器运行到FindNextFileW函数时会被暂停
        self.WaitScannerReady(self.scanner)
        
    def scan_file(sample_file):
        #向扫描器发送文件扫描请求
    	self.ScanFile(self.scanner, sample_file)
        #等待扫描器的扫描结果
        out, err = self.process.communicate()
        return out

    def close():
        self.process.kill()
        self.scanner = None
        
