More information on options is displayed when each script is ran

To convert cp2 to img:
cp2_to_img.py TEST11.CP2

To view contents :
cp2_recover.py TEST11.CP2 --probe

To check a cp2 file and move to errors folder :
cp2_check.py --verbose --errors-dir errors TEST11.CP2

To carve files from an image (like photorec)
cp2_carve.py test1.cp2 --out ./recovered

Documentation on each script is WIP

Many thanks to Hampa Hug for releasing the source code to PCE
http://www.hampa.ch/pce/
Without his cp2 parser this would of taken a lot longer.
