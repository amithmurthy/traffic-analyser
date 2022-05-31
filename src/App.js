import logo from './logo.svg';
import './App.css';
import React, { useState, useEffect } from 'react';
import { useHistory, useNavigate } from 'react-router-dom';
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
 
  function isGraphData(backendData){

    console.log(typeof(backendData))
    return true;
  }

  function updateGraph(data){
    
    var graphData = JSON.parse(data)
    console.log('breakpoint', graphData.nodes.length)
    console.log('breakpoint', graphData.edges.length)
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
    console.log(graph)
    console.log(graph['nodes'])
    console.log(graph['edges'])
   }

  function openFileExplorer(){
    window.electron.filesAPI.getFileExplorer()
    setHideProgressBar(false);
    setHideWaves(false);
    window.electron.handle('parsePercentage', (event,data) => function(event,data) {
      if (isGraphData(data)){
        // updateGraph(data);
        // setHideWaves(true);
        // setHideGraphNetwork(false);
        navigate("/GraphNetwork", {state:JSON.parse(data)});
      }
    })
  }

  return (
    <div className="App">
      <header className="App-header">
        <img src={logo} className="App-logo" alt="logo" />
        
          <div>
            {hideProgressBar?
            <button id='fileSelector' onClick={() => openFileExplorer()}>Select File </button>
              :
            // <ProgressBar bgcolor={ProgressBarData.bgcolor} completedPercentage={parseProgress} />
              // <ProgressBar completed={parseProgress} />
              
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
