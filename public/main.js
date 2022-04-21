const { BrowserWindow, app, ipcMain, dialog} = require('electron');


// const Facade = require('../engine_facade/engine_facade')
// require('@electron/remote/main').initialize()
const path = require('path');



function createWindow() {
    // Create the browser window 
    const win = new BrowserWindow({ 
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
}

app.on('ready', createWindow)

//Quit when all windows are closed 

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
        console.log('is file cancelled',file.canceled);
        if (!file.canceled) {
          // handle file input

            filePath = file.filePaths[0].toString(); 
            _event.returnValue = filePath;
        }  
    }).catch(err => {
        console.log(err)
    });
})