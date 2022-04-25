import logo from './logo.svg';
import './App.css';
import React, { useState, useEffect } from 'react';
import ProgressBar from './comps/ProgressBar';


function App() {
  
  const [hideProgressBar, setHideProgressBar ] = useState(true);

  const [parseProgress, setParseProgress] = useState(0)
  const ProgressBarData = {bgcolor:"#ef6c00"}

  function openFileExplorer(){
    window.electron.filesAPI.getFileExplorer()
    // window.electron.handle('test', (event,data) => function(event,data) {
    //   console.log(data)
    // })
    setHideProgressBar(false);
    window.electron.handle('parsePercentage', (event,data) => function(event,data) {
      console.log('renderer', data)
      setParseProgress(data)
    })
  }

  useEffect(() => {}, [parseProgress])

 
  return (
    <div className="App">
      <header className="App-header">
        <img src={logo} className="App-logo" alt="logo" />
          
          <div>
            {hideProgressBar?
            <button id='fileSelector' onClick={() => openFileExplorer()}>Select File </button>
              :
              <ProgressBar bgcolor={ProgressBarData.bgcolor} completedPercentage={parseProgress} />
            } 
          </div>
      </header>
      

    </div>
  );
}

export default App;
