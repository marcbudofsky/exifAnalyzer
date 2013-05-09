#!/usr/bin/python
# -*- coding: utf-8 -*-

##
# EXIF Analyzer
# Copyright (C) 2013 Marc Budofsky <marcbudofsky@isis.poly.edu>
#
# External Dependencies:
#  The Sleuth Kit (TSK) 4.0.2 <https://github.com/kfairbanks/sleuthkit>
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
# along with this program. If not, see <http://www.gnu.org/licenses/>.
##

__author__ = "Marc Budofsky"
__version__ = "0.1"
__license__ = "GPLv3"


# === Imports =========================================================================
import os
import csv
import sys
import math
import time
import curses
import hashlib
import logging
import argparse
import datetime
import mimetypes
import subprocess

## Non-Standard Libraries
try:
    import simplekml
    
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    
    from pygeocoder import Geocoder
    
    from sqlalchemy import Column, Integer, Float,String
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy import create_engine
except ImportError as error:
    print "You don't have module %s installed" % error.message[16:]
    sys.exit()

# === Globals =========================================================================
Base = declarative_base()

logging.basicConfig()
logging.getLogger('sqlalchemy.engine').setLevel(logging.ERROR)

# === Database Record Class ===========================================================
## From `IP_Domain_KML.py`
class DBRecord(Base):

    __tablename__ = 'exif'

    id = Column(Integer,primary_key = True)
    Filename = Column(String)
    Make = Column(String)
    Model = Column(String)
    Software = Column(String)
    DateTime = Column(String)
    Latitude = Column(Float) 
    Longitude = Column(Float)


    def __init__(self,Filename,Make,Model,Software,DateTime,Latitude,Longitude):
        self.Filename=Filename
        self.Make=Make
        self.Model=Model
        self.Software=Software
        self.DateTime=DateTime
        self.Latitude=Latitude
        self.Longitude=Longitude

# === File Carving Class ==============================================================
class fileCarve(object):
    def __init__(self,diskimage,tmpdir):
        self.diskimage = diskimage
        self.dir = tmpdir

    def carve(self):
        if not os.path.exists(self.diskimage): return False
        try:
			subprocess.check_output(["tsk_recover","-e",self.diskimage,self.dir])
			return True
        except:
            return False

# === Exif Analysis Class =============================================================
class exifAnalysis(object):
    def __init__(self, directory = "", diskimage = "", filename = "exif", debug = False):
        self.dir = directory
        self.debug = debug
        self.filename = filename
        self.diskimage = diskimage

        if (self.dir == "" and self.diskimage == ""):
            print "Error: A directory or disk image is required"
            sys.exit()

        if (self.dir != "" and self.diskimage != ""):
            print "Error: Input Directory and Disk Image specified; these options are not compatible with each other."
            sys.exit()
    
        if (self.dir != ""):
            if not os.path.exists(self.dir):
                print "Error: directory '%s' does not exist" % self.dir
                sys.exit()

        if (self.diskimage != ""):
            directory = os.path.dirname(os.path.abspath(__file__)) + '/extract/'
            if not os.path.exists(directory): os.mkdir(directory)
            fileCarver = fileCarve(self.diskimage, directory)
            if not fileCarver.carve():
                print "Error: Disk Image could not be carved."
                sys.exit()
            print "'%s' extracted into %s\n\n" % (self.diskimage, directory)
            self.dir = directory
        
        self.imgCnt  = 0
        self.exifCnt = 0
        self.gpsCnt  = 0
        
        self.data    = []
        self.grouped = {}
        
        curses.setupterm()
        self.width = curses.tigetnum('cols') if (curses.tigetnum('cols') % 2 == 0) else curses.tigetnum('cols') - 1
        
        mimetypes.init()
        
    def processImages(self):
        for dirname, dirnames, filenames in os.walk(self.dir):
            for filename in filenames:
                mime, enc = mimetypes.guess_type(os.path.join(dirname, filename))
                if "image" in str(mime):
                    self.imgCnt += 1
                    try:
                        img = Image.open(os.path.join(dirname, filename))
                    except Exception, e:
                        continue
                    exif = self.getExifData(img)
                    if not self.dict_is_empty(exif):
                        self.exifCnt += 1
                        tmp = {}
                        tmp['Filename'] = os.path.join(dirname, filename)
                        tmp['Make'] = self.parseExif(exif, 'Make')
                        tmp['Model'] = self.parseExif(exif, 'Model')
                        tmp['Software'] = self.parseExif(exif, 'Software')
                        tmp['DateTime'] = self.parseExif(exif, 'DateTime')
                        
                        if self.debug: self.printDebugInformation(tmp)
                            
                        try:
                            lat = self.getGPS(exif['GPSInfo'][2], exif['GPSInfo'][1])
                            lon = self.getGPS(exif['GPSInfo'][4], exif['GPSInfo'][3])
                        except:
                            lat = 0.0
                            lon = 0.0
                        
                        if lat and lon:
                            self.gpsCnt += 1
                            
                            if self.debug: print "\tLocation: %s" % ((lat, lon),)
                            
                        tmp['Latitude'] = lat
                        tmp['Longitude'] = lon
                            
                        self.data.append(tmp)
	    
    def printDebugInformation(self, tmp):
        print "%s:" % tmp['Filename']
        print "\tMake: %s" % tmp['Make']
        print "\tModel: %s" % tmp['Model']
        print "\tSoftware: %s" % tmp['Software']
        print "\tTime: %s" % tmp['DateTime']
    
    ## http://stackoverflow.com/questions/6460381/translate-exif-dms-to-dd-geolocation-with-python                    
    def getExifData(self, img):
        ret = {}
        try:
            info = img._getexif()
            for tag, value in info.items():
                decoded = TAGS.get(tag, tag)
                ret[decoded] = value
        except Exception, e:
            ret = ret
        
        return ret
    
    ## http://stackoverflow.com/questions/1342000/how-to-replace-non-ascii-characters-in-string
    def parseExif(self, exif, tag):
        try:
            return "".join(char for char in exif[tag] if ord(char) < 128).replace('\x00', '').strip().encode("ascii", "ignore")
        except Exception, e:
            return "Unknown"
    
    ## http://stackoverflow.com/questions/6460381/translate-exif-dms-to-dd-geolocation-with-python    
    def getGPS(self, data, ref):
        coords = [float(x)/float(y) for x, y in data]
        res =  coords[0] + coords[1]/60 + coords[2]/3600
        return res if ref not in ('S', 'W') else res * -1
    
    def printData(self):
        print self.data
        
    def printGrouped(self):
        print "# === Grouped Data %s" % ("=" * (self.width - 19))
        for make in sorted(self.grouped.iterkeys()):
            if make == "Unknown": continue
            print "Make: %s" % make
            for model in sorted(self.grouped[make].iterkeys()):
                print "\tModel: %s" % model
                for software in sorted(self.grouped[make][model].iterkeys()):
                    print "\t\tSoftware: %s" % software
                    for file in self.grouped[make][model][software]:
                        print "\t\t\tFilename: %s" % file
        print "# %s" % ("=" * (self.width - 2))
    
    def analyzeData(self, printData = False):
        statistics = {}
        coordinates = {}
        
        for el in self.data:
            if el['Make'] not in statistics:
                statistics[el['Make']] = {}
                statistics[el['Make']]['cnt'] = 1
            else:
                statistics[el['Make']]['cnt'] += 1
            
            if el['Model'] not in statistics[el['Make']]:
                statistics[el['Make']][el['Model']] = {}
                statistics[el['Make']][el['Model']]['cnt'] = 1
            else:
                statistics[el['Make']][el['Model']]['cnt'] += 1
            
            statistics[el['Make']][el['Model']][el['Software']] = statistics[el['Make']][el['Model']][el['Software']] + 1 if el['Software'] in statistics[el['Make']][el['Model']] else 1
            
            ## Basic Grouping
            if el['Make'] not in self.grouped: self.grouped[el['Make']] = {}
            if el['Model'] not in self.grouped[el['Make']]: self.grouped[el['Make']][el['Model']] = {}
            if el['Software'] not in self.grouped[el['Make']][el['Model']]: self.grouped[el['Make']][el['Model']][el['Software']] = []
            
            self.grouped[el['Make']][el['Model']][el['Software']].append(el['Filename'])
            ##
            
            if el['Latitude'] == 0.0 or el['Longitude'] == 0.0:
                continue
                
            locationFound = False
            for coord in coordinates:
                if self.distance(coord, (el['Latitude'], el['Longitude'])) < .5:
                    coordinates[coord]['cnt'] += 1
                    locationFound = True
                    
            if not locationFound:
                coordinates[(el['Latitude'], el['Longitude'])] = {}
                coordinates[(el['Latitude'], el['Longitude'])]['cnt'] = 1
        
        if printData:
            self.printStatistics(statistics)
            if len(coordinates) > 0:
                 self.printCoordinates(coordinates)
        
    def printStatistics(self, statistics):
        print "\n%s" % ("*" * self.width)
        spaces = (" " * ((self.width - len("Analysis") - 2) / 2))
        print "*%sAnalysis%s*" % (spaces, spaces) 
        print "%s" % ("*" * self.width)
        self.printAnalysis("Images Containing exif Data: " + str(self.exifCnt) + "/" + str(self.imgCnt), (100*float(self.exifCnt))/float(self.imgCnt))
        self.printAnalysis("Images Containing GPS Data: " + str(self.gpsCnt) + "/" + str(self.exifCnt), (100*float(self.gpsCnt))/float(self.exifCnt))
    
        print "\nManufacturer Statistics: "
        for make in statistics:
            self.printAnalysis("  Make: " + make + "; Count: " + str(statistics[make]['cnt']), (100*float(statistics[make]['cnt']))/float(self.exifCnt))
            for model in statistics[make]:
                if model == 'cnt': continue
                self.printAnalysis("    Model: " + model + "; Count: " + str(statistics[make][model]['cnt']), (100*float(statistics[make][model]['cnt']))/float(statistics[make]['cnt']))
                for software in statistics[make][model]:
                    if software == "cnt": continue
                    self.printAnalysis("      Software: " + software + "; Count: " + str(statistics[make][model][software]), (100*float(statistics[make][model][software]))/float(statistics[make][model]['cnt']))
            print ""
    
    def printCoordinates(self, coordiantes):
        print "Coordinate Lookup: (" + str(len(coordiantes)) + ")"
        dispLen = len(str(coordiantes[max(coordiantes, key = lambda x: coordiantes.get(x) )]['cnt']))
        for key in coordiantes:
            print "[%*d] (%.3f, %.3f) -->" % (dispLen, coordiantes[key]['cnt'], key[0], key[1]),
            successfulLookup = False
            lookupCount      = 0
            while (not successfulLookup) and (lookupCount < 5):
                try:
                    print Geocoder.reverse_geocode(key[0], key[1])
                    successfulLookup = True
                except Exception, e:
                    # print e
                    if "ZERO_RESULTS" in e:
                        lookupCnt = float('Inf')
                        break
                    time.sleep(.5)
                    lookupCount += 1
            if (not successfulLookup) or (lookupCount > 5):
                print "No results found..."
        print ""
    
    def printAnalysis(self, txt, percent):
        percent = ("%.1f" % percent)
        percent = (" " * (5 - len(percent))) + ("%s" % percent) + "%"
        print "%s %s[%s]" % (txt, ("." * (self.width - len(txt) - len(percent) - 3)), percent)

    ## http://www.joelverhagen.com/blog/2011/02/md5-hash-of-file-in-python/
    def md5Checksum(self, filePath):
        with open(filePath, 'rb') as data:
            md5 = hashlib.md5()
            while True:
                tmp = data.read(8192)
                if not tmp:
                    break
                md5.update(tmp)
            return md5.hexdigest()

    def sha1Checksum(self, filePath):
        with open(filePath, 'rb') as data:
            sha1 = hashlib.sha1()
            while True:
                tmp = data.read(8192)
                if not tmp:
                    break
                sha1.update(tmp)
            return sha1.hexdigest()

    def sha256Checksum(self, filePath):
        with open(filePath, 'rb') as data:
            sha256 = hashlib.sha256()
            while True:
                tmp = data.read(8192)
                if not tmp:
                    break
                sha256.update(tmp)
            return sha256.hexdigest()

    def exportData(self):
        print "Exporting Data...",
        outputDir = os.path.dirname(os.path.abspath(__file__)) + '/output/'
        if not os.path.exists(outputDir): os.mkdir(outputDir)
        self.saveKML(outputDir, self.filename)
        self.saveCSV(outputDir + self.filename + ".csv")
        self.saveSQL(outputDir + self.filename + ".sqlite")
        self.createReport(outputDir + self.filename + ".html")
        print "Done"
        print "Data saved in %s" % outputDir

    def createReport(self, filename):
        report = open(filename, "w")
        report.write("<!DOCTYPE html>\n")
        report.write("<html>\n")
        report.write("<head>\n")
        report.write("<title>EXIF Analysis Report: %s</title>\n" % datetime.datetime.now().strftime("%B %d, %Y %I:%M%p"))
        report.write("</head>\n")
        report.write("<body>\n")
        if (self.diskimage != ""):
            report.write("<h3>Disk Image: %s</h3>\n" % self.diskimage)
            report.write("<h5>Files extracted to: '%s'</h5>\n" % self.dir)
            report.write("Disk Image Information:<br />\n")
            fsstatOut = subprocess.check_output(["fsstat",self.diskimage])
            imageInfo = fsstatOut.split("\n")[:-18]
            for tmp in xrange(len(imageInfo)):
                report.write("%s<br />\n" % (imageInfo[tmp]))
            report.write("<br />\n")
        else:
            report.write("<h1>Directory: %s</h1>" % self.dir)
        report.write("<h2>EXIF Analysis:</h2>\n")
        for el in self.data:
            report.write("File: <a href='img/%s'>%s</a><br />" % (el['Filename'].split('/')[-1], el['Filename'].split('/')[-1]))
            descriptionString = ""
            for tmp in sorted(el):
                if tmp == "Filename": continue
                descriptionString += tmp + ": " + str(el[tmp]) + "<br />\n"
            descriptionString += "MD5: " + self.md5Checksum(el['Filename']) + "<br />\n"
            descriptionString += "SHA1: " + self.sha1Checksum(el['Filename']) + "<br />\n"
            descriptionString += "SHA256: " + self.sha256Checksum(el['Filename']) + "<br />\n"
            report.write("%s<br />" % descriptionString)
        report.write("</body>\n")
        report.write("</html>")
        report.close()

    ## From `IP_Domain_KML.py`  
    def saveKML(self, outputDir, filename):
        kml = simplekml.Kml()
        kmz = simplekml.Kml()
    
        for el in self.data:
            if el['Latitude'] == 0.0 or el['Longitude'] == 0.0:
                continue
            descriptionString = ""
            for tmp in sorted(el):
                descriptionString += tmp + ": " + str(el[tmp]) + "\n"
            descriptionString += "MD5: " + self.md5Checksum(el['Filename']) + "\n"
            descriptionString += "SHA1: " + self.sha1Checksum(el['Filename']) + "\n"
            descriptionString += "SHA256: " + self.sha256Checksum(el['Filename']) + "\n"
            name = el['Filename'].split('/')[-1]
            if not os.path.exists(outputDir + 'img/'):
                os.mkdir(outputDir +  'img/')
            resizePath = outputDir +  'img/' + name
            if not os.path.isfile(resizePath):
                self.resizeImage(el['Filename'], resizePath, (600,400))
            kml.newpoint(name = name,
                         coords = [(el['Longitude'],
                                    el['Latitude']
                                  )]
                         )
            pnt = kmz.newpoint(name = name,
                               description = descriptionString,
                               coords = [(el['Longitude'],
                                          el['Latitude']
                                        )]
                               )
            pnt.style.iconstyle.icon.href = resizePath
                        
        kml.save(outputDir + filename + ".kml")
        kmz.savekmz(outputDir + filename + ".kmz")
    
    ## From `IP_Domain_KML.py`  
    def saveCSV(self, filename):
        keys = self.data[0].keys()
        
        csv_formatted = [[el[key] for key in keys] for el in self.data]
        
        with open(filename,'w') as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow(keys)
            csvwriter.writerows(csv_formatted)
    
    ## From `IP_Domain_KML.py`    
    def saveSQL(self, filename):
        engine = create_engine('sqlite:///'+filename, echo=False)
        Base.metadata.create_all(engine)

        Session = sessionmaker(bind=engine)    
        session = Session()

        for el in self.data:
            dbrecord = DBRecord(**el)

            session.add(dbrecord)
            session.commit()
    
    ## http://stackoverflow.com/questions/400788/resize-image-in-python-without-losing-exif-data
    def resizeImage(self, source_path, dest_path, size):
        img = Image.open(source_path)
        img = img.resize(size, Image.ANTIALIAS)
        img.save(dest_path)
        
    def dict_is_empty(self, d):
        for k in d:
            return False
        return True
    
    ## http://www.johndcook.com/python_longitude_latitude.html
    def distance(self, (lat1, long1), (lat2, long2)):
        degrees_to_radians = math.pi/180.0
        
        phi1 = (90.0 - lat1)*degrees_to_radians
        phi2 = (90.0 - lat2)*degrees_to_radians
        
        theta1 = long1*degrees_to_radians
        theta2 = long2*degrees_to_radians
    
        cos = (math.sin(phi1)*math.sin(phi2)*math.cos(theta1 - theta2) + 
               math.cos(phi1)*math.cos(phi2))
        arc = math.acos( cos )

        return arc * 3959

# === Execution Mode ==================================================================
def main():
    parser = argparse.ArgumentParser(description="Analyze GPS and EXIF data for a directory of pictures or from a carved disk image.")
    
    parser.add_argument('-d', '--dir', dest="inputdirectory",
                        metavar = '/path/to/pictures/',
                        type = str,
                        help = "Directory that contains images to analyze",
                        default = "")
    parser.add_argument('-i', '--image', dest="diskimage",
                        metavar = '/path/to/diskimage',
                        type = str,
                        help = "Disk Image to carve pictures from",
                        default = "")
    parser.add_argument('--debug', dest = 'debug',
                        metavar = 'DEBUG',
                        action = "store_const",
                        const = True,
                        help = "Enable debug mode",
                        default = False)
    parser.add_argument('-o', '--output', dest = 'output',
                        metavar = 'OUTPUT',
                        type = str,
                        help = "Output filename",
                        default = "exifAnalysis")
    parser.add_argument('--version', action='version', version='%(prog)s ' + __version__)
    
    args = parser.parse_args()
            
    exifAnalyzer = exifAnalysis(args.inputdirectory, args.diskimage, args.output, args.debug)
    exifAnalyzer.processImages()
    exifAnalyzer.analyzeData(True)
    if args.debug:
        exifAnalyzer.printGrouped()
    exifAnalyzer.exportData()

if __name__ == '__main__':
    main()
