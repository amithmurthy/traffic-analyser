import { elastic as Menu } from 'react-burger-menu';
import React from 'react';
import './Sidebar.css';
import { useNavigate } from 'react-router-dom';


export default props => {
    const navigate = useNavigate()

    const homePageNavigator = () => {
        window.electron.sessionStorageAPI.getHomePageData()
        window.electron.handle('getHomePageData', (event,data) => function(event,data) {
            navigate("/home", {state: JSON.parse(data)})
        })
    }

    return (
        <Menu>
            
            <a className="menu-item" onClick={() => homePageNavigator()}>
                Home
            </a>
            <a className="menu-item" href='/nodes'>
                Nodes
            </a>

        </Menu>
    )

}