const { contextBridge, ipcRenderer } = require('electron');


contextBridge.exposeInMainWorld('electron', {
    filesAPI:{
        getFileExplorer(){
            var filePath = ipcRenderer.sendSync('fileExplorer');
            var _parser = ipcRenderer.send('parser', filePath);
        }
    },
    //handle is the api for receiving data in the DOM components from main process.
    handle: (channel, callable, event, data) => ipcRenderer.on(channel, callable(event, data)),
    facadeAPI: {
        sendRequest(request, key){
            var facade = ipcRenderer.send('facade', request, key);
        }
    },
    sessionStorageAPI: {
        // setHomePageData(data){
        //     const setter = ipcRenderer.send('storeHomePageData', data)
        // },
        // getHomePageData(){
        //     const getter = ipcRenderer.send('getHomePageData')
        // }
        setSessionStorageItem(key, value){
            const setter = ipcRenderer.send('setSessionStorageItem', key, value)
        },
        getSessionStorageItem(key){
            const getter = ipcRenderer.send('getSessionStorageItem', key)
        }
    },
    nodeAPI:{
        getNodeData(nodeId){
            ipcRenderer.send()
        }
    }
})