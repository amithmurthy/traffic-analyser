const { contextBridge, ipcRenderer } = require('electron');


contextBridge.exposeInMainWorld('electron', {
    filesAPI:{
        getFileExplorer(){
            console.log('works');
            var filePath = ipcRenderer.sendSync('fileExplorer');
            var _parser = ipcRenderer.send('parser', filePath);
        }
    },
    handle: (channel, callable, event, data) => ipcRenderer.on(channel, callable(event, data))
})