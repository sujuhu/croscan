#coding = utf-8
from SimpleXMLRPCServer import SimpleXMLRPCServer
#from xml.dom import minidom
from xml.etree.ElementTree import ElementTree
from xml.etree.ElementTree import Element
from xml.etree.ElementTree import SubElement
from xml.etree.ElementTree import dump
from xml.etree.ElementTree import Comment
from xml.etree.ElementTree import tostring

def load_scanner_config( cfg_file, i ):    
    name = "scanner%d" % i
    scanner_name = ElementTree(file=cfg_file).getroot().find('%s/name'%name).text
    cmdline = ElementTree(file=cfg_file).getroot().find('%s/cmdline'%name).text
    flush = ElementTree(file=cfg_file).getroot().find('%s/flush'%name).text
    return scanner_name, cmdline, int(flush)
    
if __name__ == "__main__":
    pass    