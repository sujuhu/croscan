#coding = utf-8
import os,sys
import setting
import avctrl

scanners = {}
for i in range(10):
	name, param, flush_method = setting.load_scanner_config("scanner.xml", i)
	cmdline = os.path.join(sys.path[0], name)
	cmdline = os.path.join(cmdline, param)
	cmdline = cmdline.replace("$logfile", "d:\scanner%d.log" % i)
	cmdline = cmdline.replace("$virusDir", "d:\\sample")
	print cmdline
	scanner = avctrl.VirusScanner(name, cmdline, flush_method)
	scanners[name] = scanner
	print "Scanner %s load" % name

file_list = os.listdir("d:\\sample")
print file_list
sys.exit()

for sample in file_list:
	report = {}
	print "Sample %s" % sample
	for scanner in scanners:
		output = scanner.scan_file(sample)
		report[name] = output
	print report

