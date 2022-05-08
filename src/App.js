import logo from './logo.svg';
import './App.css';
import React, { useState, useEffect } from 'react';
// import ProgressBar from './comps/ProgressBar';
import { Waves } from 'loading-animations-react'

function App() {
  
  const [hideProgressBar, setHideProgressBar ] = useState(true);

  const [parseFinished, setParseFinished] = useState(false);

  // const [parseProgress, setParseProgress] = useState(0)
  // const ProgressBarData = {bgcolor:"#ef6c00"}

  function openFileExplorer(){
    window.electron.filesAPI.getFileExplorer()
    setHideProgressBar(false);
    window.electron.handle('parsePercentage', (event,data) => function(event,data) {
      console.log('renderer', data)
      if(data == 'finished'){
        setParseFinished(true);
      }
    })
  }

  // useEffect(() => {}, [parseProgress])

 
  return (
    <div className="App">
      <header className="App-header">
        <img src={logo} className="App-logo" alt="logo" />
          
          <div>
            {hideProgressBar?
            <button id='fileSelector' onClick={() => openFileExplorer()}>Select File </button>
              :
              // <ProgressBar bgcolor={ProgressBarData.bgcolor} completedPercentage={parseProgress} />
              
              <div>
                {
                  parseFinished?
                  <Waves waveColor="cyan" backgroundColor="#000" />
                  :
                  <div></div>
                }
              </div>
            } 
          </div>
      </header>
      

    </div>
  );
}

export default App;
