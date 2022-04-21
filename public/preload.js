const { contextBridge, ipcRenderer } = require('electron');
const { PythonShell } = require("python-shell");

contextBridge.exposeInMainWorld('electron', {
    filesAPI:{
        getFileExplorer(){
            console.log('works');
            var filePath = ipcRenderer.sendSync('fileExplorer');
            
            var options = {
                mode: 'text',
                encoding: 'utf8',
                scriptPath: path.join(__dirname, '/../engine/'),
                pythonPath: path.join(__dirname, '/../engine/env/Scripts/python.exe'),
                args: [filePath]
            };
            
            let parser = new PythonShell('test_parser.py', options);
            parser.on('message', function(message){
                console.log('PYTHON SHELL MESSAGE', message);
            })
        }
    }
})