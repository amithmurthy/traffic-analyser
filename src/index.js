import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import App from './App';
import GraphNetwork from './pages/GraphNetwork';
import UnAuthorised from './pages/_401';
import Home from './pages/Home';
import NodeView from './pages/NodeView';
import Nodes from './pages/Nodes'
import reportWebVitals from './reportWebVitals';
import {
  BrowserRouter as Router,
  Routes,
  Route,
} from "react-router-dom";
import ProtectedRoute from './comps/ProtectedRoute'

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  // <React.StrictMode>
    <Router>
      <Routes>
        <Route path="/" element={<App/>} />
        <Route path="/GraphNetwork" element={<GraphNetwork/>}/>
        <Route path="/home" element={<Home />} />
        <Route path="/nodes" element={<Nodes />} />
        <Route path='/nodes/:nodeId' element={<NodeView />} />
        <Route path={"/404"} element={<UnAuthorised />} />
      </Routes>
    </Router>
  // </React.StrictMode>
);

// If you want to start measuring performance in your app, pass a function
// to log results (for example: reportWebVitals(console.log))
// or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals
reportWebVitals();
