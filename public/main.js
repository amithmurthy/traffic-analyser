const { BrowserWindow, app, ipcMain, dialog, session} = require('electron');
const { PythonShell } = require("python-shell");
// const {localStorage, sessionStorage} = require('electron-browser-storage');


// const Facade = require('../engine_facade/engine_facade')
// require('@electron/remote/main').initialize()
const path = require('path');
const { request } = require('http');
const { assert } = require('console');
const isDev = require('electron-is-dev');


let win = null;

var pythonOptions = {
    mode: 'text',
    encoding: 'utf8',
    scriptPath: path.join(__dirname, '/../engine/'),
    pythonPath: '/Users/amithmurthy/Documents/projects/traffic-analyser/engine/env/bin/python3',
    args: []
};


function createWindow() {
    // Create the browser window 
    win = new BrowserWindow({ 
        width: 800,
        height: 600, 
        webPreferences: {
            nodeIntegration: false,
            enableRemoteModule: true,
            worldSafeExecuteJavaScript: true,
            contextIsolation: true,
            preload: path.join(__dirname, 'preload.js')
        }
    })
    win.loadURL('http://localhost:3000')
    // win.loadURL(
    //     isDev ? 'http://localhost:3000'
    //     : `file://${path.join(__dirname, '../build/index.html')}`
    // )
    // win.loadURL(`file://${path.join(__dirname, '../build/index.html')}`)
    win.webContents.openDevTools()
}

app.on('ready', createWindow)


// Quit when all windows are closed 

app.on('window-all-closed', function() {
    //On OS X applications and their menu bar stay active
    // until the user quits explicitly with Cmd + Q
    if (process.platform !=='darwin'){
        app.quit()
    }
})

app.on('activate', function(){
    // On OS X it is common to re-create a window in the app when 
    // the dock icon is clicked and there are not other windows open
    if (BrowserWindow.getAllWindows().length === 0){
        createWindow()
    }
})

ipcMain.on('fileExplorer', (_event, args) => {
    // dialog.showOpenDialog();  
    var filePath = undefined;
    dialog.showOpenDialog({
        title: 'Select the File to be uploaded',
        defaultPath: path.join(__dirname, '../assets/'),
        // Restricting the user to only Text Files.
        filters: [
            {
                name: 'pcap',
                extensions: ['pcap', 'pcapng']
            }, ],
        // Specifying the File Selector Property
        properties: ['openFile']
    }).then(file => {
        // Stating whether dialog operation was
        // cancelled or not.
        console.log('is file cancelled', file.canceled);
        if (!file.canceled) {
          // handle file input
            filePath = file.filePaths[0].toString(); 
            _event.returnValue = filePath;
        }  
    }).catch(err => {
        console.log(err)
    });
})


const setSessionStorageItem = (key, value) => {
    // sets session storage item
    console.log('setting session storage with key:', key)
    win.webContents.executeJavaScript(`window.sessionStorage.setItem('${key}', '${value}');`)
}   

const getSessionStoargeItem = (key) => {
    // returns a Promise object
    console.log('getting session storage item with key', key)
    return win.webContents.executeJavaScript(`window.sessionStorage.getItem('${key}');`, true)
}


ipcMain.on('storeHomePageData', (_event, inData) => {
    // win.webContents.executeJavaScript(`window.sessionStorage.setItem('${'homePageData'}', '${JSON.stringify(inData)}');`)
    // win.webContents.executeJavaScript(`window.sessionStorage.getItem('${'homePageData'}');`, true)
    // .then(result => {
    //     console.log(JSON.parse(result))
    // })
    setSessionStorageItem('homePageData', inData);
})

ipcMain.on('setSessionStorageItem', (_event, key, value) => {
    console.log('setting session storage item', typeof(value))
    // main interface for session storage functions
    setSessionStorageItem(key, value)
})

ipcMain.on('getSessionStorageItem', (_event, key) => {
    getSessionStoargeItem(key)
    .then(value => {
        _event.sender.send('getSessionStorageItem', value)
    })
})


ipcMain.on('getHomePageData', (_event) => {
    getSessionStoargeItem('homePageData')
    .then(value => {
        console.log('sending session storage value to renderer')
        _event.sender.send('getHomePageData', value);
    })    
})


ipcMain.on('parser', (_event, filePath) => {
    
    pythonOptions.args.push(filePath)
    console.log('sending parse request to engine')
    let parser = new PythonShell('test_parser.py', pythonOptions);
    parser.on('message', function(message){
        _event.sender.send('routeToHome', message);
    })
})


ipcMain.on('facade', (_event, request, key) =>{
    
    pythonOptions.args.pop();
    pythonOptions.args.push(JSON.stringify(request));
    let facade = new PythonShell('facade.py', pythonOptions);
    // facade.send(request);
    const renderChannel = Object.keys(request)[0]
    facade.on('message', function(message){
        console.log('python message received')
        _event.sender.send(renderChannel, message);  
        facade.end(function(err, code, output){
            if (err){
                console.log(err)
            }
        })
    })
    
})



