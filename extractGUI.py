#!/bin/env python 3.1

from tkinter import *
from tkinter import ttk
from tkinter import messagebox
from tkinter import filedialog
import configparser
import extract

root = Tk()
root.title('Extract AWS Audit Trails')

recordsDir = StringVar()
csvFile = StringVar()
eventsFile = StringVar()
showAll = IntVar()
showAll.set(0)

def getRecordsDir ():
    recordsDir.set(filedialog.askdirectory(parent=root, mustexist=True))

def getCSVFile ():
    csvFile.set(filedialog.asksaveasfilename(parent=root))

def geteventsFile ():
    eventsFile.set(filedialog.askopenfilename(parent=root, defaultextension='.ini'))

def chkAndExtract (*args):
    ok = True
    messages = []
    if recordsDir.get() == '':
        ok = False
        messages.append('Input directory not specified.')
    if csvFile.get() == '':
        ok = False
        messages.append('Output file not specified.')
    if eventsFile.get() == '':
        ok = False
        messages.append('Events specification file not specified.')
    if ok:
        confParser = configparser.SafeConfigParser({'Reported':'', 'Ignored':''})
        confParser.read(eventsFile.get())
        eventsReported = confParser.get('Events', 'Reported').split()
        eventsIgnored = confParser.get('Events', 'Ignored').split()

        ok, messages = extract.calculate(recordsDir.get(), csvFile.get(), eventsReported, eventsIgnored, showAll.get() == 1)
    
    if ok:
        messagebox.showinfo(parent=topFrame, message='Extraction completed.', title='Information')
    else:
        messagebox.showerror(parent=topFrame, message='\n'.join(messages), title='Error')
    return ok

topFrame = ttk.Frame(root, padding=5)
topFrame.grid(column=0, row=0, sticky=(N, W, E, S))
topFrame.columnconfigure(0, weight=1)
topFrame.rowconfigure(0, weight=1)
ttk.Button(topFrame, text='Records Directory', command=getRecordsDir).grid(column=0, row=1, sticky=W)
ttk.Label(topFrame, textvariable=recordsDir).grid(column=1, row=1, sticky=W)
ttk.Button(topFrame, text='Output File', command=getCSVFile).grid(column=0, row=2, sticky=W)
ttk.Label(topFrame, textvariable=csvFile).grid(column=1, row=2, sticky=W)
ttk.Button(topFrame, text='Events File', command=geteventsFile).grid(column=0, row=3, sticky=W)
ttk.Label(topFrame, textvariable=eventsFile).grid(column=1, row=3, sticky=W)
ttk.Checkbutton(topFrame, text='Show All Events', variable=showAll).grid(column=0, row=4, columnspan=2, sticky=EW)
ttk.Button(topFrame, text='Extract', command=chkAndExtract).grid(column=0, row=5, columnspan=2, sticky=EW)
for child in topFrame.winfo_children(): child.grid_configure(padx=5, pady=5)
ttk.Sizegrip(topFrame).grid(column=999, row=999, sticky=(S, E))

root.mainloop()
