#!/usr/bin/python

import os, sys
from Tkinter import *
import gobject

class Application(Frame):

    def quit(self):
        self.hangup()
        self.destroy()

    def makecall(self):
        self._pipeout.write("C")
        self._pipeout.flush()

    def hangup(self):
        self._pipeout.write("H")
        self._pipeout.flush()

    def hello(self):
        self._pipeout.write("!")
        self._pipeout.flush()

    def createWidgets(self):
        self.master.title("audioengine")
        self.frame1 = Frame(self)
        self.frame1.pack();
        self.frame2 = Frame(self)
        self.frame2.pack();

        self._displaytext = StringVar()
        self.label = Label(master=self.frame1, width=30, height=5, fg="sea green", bg="black", textvariable=self._displaytext, font=("Helvetica", 16));
        self.label.pack();
        self.QUIT = Button(self.frame2)
        self.QUIT["text"] = "Quit"
        self.QUIT["fg"]   = "red"
        self.QUIT["command"] =  self.quit
        self.QUIT.pack({"side": "left"})

        self.call = Button(self.frame2)
        self.call["text"] = "Call/Answer"
        self.call["fg"] = "dark green";
        self.call["command"] = self.makecall
        self.call.pack({"side": "left"})

        self.call = Button(self.frame2)
        self.call["text"] = "Hangup"
        self.call["fg"] = "red";
        self.call["command"] = self.hangup
        self.call.pack({"side": "left"})

    def _pipein_callback(self, source, condition):
        #ret = self._pipein.readline()
        ret = os.read(self._pipein.fileno(), 256)
        self._displaytext.set(ret)
        return True;

    def __init__(self, master=None):
        Frame.__init__(self, master)
        self.pack()
        self.createWidgets()
        self._pipeout = open("/tmp/aefifo_in", "w")
        self._pipein = open("/tmp/aefifo_out", "r")

        #gobject.io_add_watch(self._pipein, gobject.IO_IN, self._pipein_callback)
        self.hello()
        gobject.io_add_watch(self._pipein, gobject.IO_IN, self._pipein_callback)

    def _refreshApp(self):
        self.update()
        return True

    def destroy(self):
        self._loop.quit()

    def go(self):
        self._running = True
        gobject.idle_add(self._refreshApp)
        self._loop = gobject.MainLoop()
        self._loop.run()
        
root = Tk()
app = Application(master=root)
app.go()
