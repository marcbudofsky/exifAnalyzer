exifAnalyzer README
============

Usage
-----

usage: exifAnalyzer.py [-h] [-d /path/to/pictures/] [-i /path/to/diskimage]
                       [--debug] [-o OUTPUT] [--version]

Analyze GPS and EXIF data for a directory of pictures or from a carved disk image.

optional arguments:
  -h, --help            show this help message and exit
  -d /path/to/pictures/, --dir /path/to/pictures/
                        Directory that contains images to analyze
  -i /path/to/diskimage, --image /path/to/diskimage
                        Disk Image to carve pictures from
  --debug               Enable debug mode
  -o OUTPUT, --output OUTPUT
                        Output filename
  --version             show program's version number and exit


Dependencies
------------

Before running exifAnalyzer, you may need to install other packages on your system which exifAnalyer requires to execute properly.

exifAnalyzer uses scripts contained within The Sleuth Kit (TSK) 4.0.2. TSK can be downloaded from https://github.com/kfairbanks/sleuthkit

exifAnalyzer requires several non-standard Python libraries.  Please install them with the following command:

  $ pip install simplekml PIL pygeocoder sqlalchemy


