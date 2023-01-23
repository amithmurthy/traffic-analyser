import logo from './logo.svg';
import './App.css';
import React, { useState, useEffect } from 'react';
import {  useNavigate } from 'react-router-dom';
// import ProgressBar from './comps/ProgressBar';
// import ProgressBar from 'react-bootstrap/ProgressBar'
import { Waves } from 'loading-animations-react'
// import ProgressBar from "@ramonak/react-progress-bar";




function App() {
  
  const [hideProgressBar, setHideProgressBar ] = useState(true);

  const [hideWaves, setHideWaves] = useState(true);

  const [parseProgress, setParseProgress] = useState(0)
  const ProgressBarData = {bgcolor:"#ef6c00"}

  const [hideGraphNetwork, setHideGraphNetwork] = useState(true);

  // const graph = {
  //   nodes: [],
  //   edges: []
  // }

  const [graph, setGraph] = useState(new Map());

  const navigate = useNavigate();
  
 
  const updateMap = (key, value) => {
    setGraph(map => map.set(key, value));
  }
 
  function isValidHomePageData(backendData){
    return true;
  }

  const isSerialisedData = (data) => {
    const dataToSave = JSON.parse(data)
    console.log(JSON.parse(dataToSave.serialised))
    window.electron.sessionStorageAPI.setSessionStorageItem('serialisedSessionData', JSON.parse(dataToSave.serialised));
    return true
    // if('serialised' in JSON.parse(data)){
    //   window.electron.sessionStorageAPI.setSessionStorageItem('serialisedSessionData', data);
    //   return true
    // }
    // return false
  }

  function updateGraph(data){
    
    var graphData = JSON.parse(data)
    var nodes_list = []
    var edge_list = []
    for (let i = 0; i < graphData.nodes.length; i++){
      nodes_list.push(graphData.nodes[i])
    }
    updateMap('nodes', nodes_list)
    for (let j =0; j < graphData.edges.length; j++){
      edge_list.push(graphData.edges[j])
    }
    updateMap('edges', edge_list)
  }

  function openFileExplorer(){
    window.electron.filesAPI.getFileExplorer()
    setHideProgressBar(false);
    setHideWaves(false);
    window.electron.handle('serialisedSessionData', (event, data) => function(event, data) {
      if (isSerialisedData(data)){
        const home_page_data_request = {'pipe_home_page_data': null}
        window.electron.facadeAPI.sendRequest(home_page_data_request, 'pipe_home_page_data')
      }
    })

    window.electron.handle('facade', (event, data) => function(event, data){
      if (isValidHomePageData(data)){
        navigate("/home", {state: JSON.parse(data)})
      }
    })
    // window.electron.handle('parsePercentage', (event,data) => function(event,data) {
    //   if (isSerialisedData(data)){
    //     // window.electron.sessionStorageAPI.setHomePageData(JSON.stringify(JSON.parse(data)));
    //     navigate("/home", {state:JSON.parse(data)});
    //   }
    // })
  }

  return (
    <div className="App">
      <header className="App-header">
        <img src={logo} className="App-logo" alt="logo" />

          <div>
            {hideProgressBar ?
            <button id='fileSelector' onClick={() => openFileExplorer()}>Select File </button>
              :  
              <div>
                {
                  hideWaves?
                  <div></div>
                  :
                  <Waves waveColor="cyan" backgroundColor="#000" text="Parsing..."/>
                }
              </div>
            } 
          </div>
      </header>
    </div>
  );
}

export default App;