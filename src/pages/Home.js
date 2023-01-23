import { useLocation, useNavigate } from 'react-router-dom';
import NetworkGraph from '../comps/NetworkGraph';
import Sidebar from '../comps/Sidebar';
import { Card, CardContent } from '@mui/material';
import ScrollTable from '../comps/ScrollTable';
import { useEffect, useState } from 'react';

// style={{alignItems: 'center'}}
const Home = () => {

    const location = useLocation();
    const networkData = location.state;
    const [sessionData, setSessionData] = useState()

    // if (! networkData){
        // window.electron.sessionStorageAPI.getHomePageData()
        // window.electron.handle('getHomePageData', (event,data) => function(event,data) {
        //     homeData = data
        //     setSessionData(data)
        // })
    // }    

    // useEffect(() => {
    // window.electron.sessionStorageAPI.getHomePageData()
    // window.electron.handle('getHomePageData', (event,data) => function(event,data) {
    //     setSessionData(data)
    // })
    
    // })
    console.log('networkData in Home Page', networkData)
    
    

    const nodeTableColumns = [
        { id: 'mac_addr', label: 'MAC ADDRESS (ID)', minWidth: 170 }, 
        { id: 'uplink_total', label: 'Uplink Total (MB)', minWidth: 200 },
        { id: 'downlink_total', label: 'Downlink Total (MB)', minWidth: 200 },   
    ]

    return (
    <>  
        <Sidebar pageWrapId={'page-wrap'} outerContainerId={'outer-container'} />
        <div style={{ height: '100vh' }}>
            <div className='centered'>
                <h1 > Home </h1>
            </div>
            <div className='centered'>
            <Card sx={{ width:'100vh', height:'75vh' }} >
                <CardContent>
                    <NetworkGraph data={networkData.network_graph} />
                </CardContent>
            </Card>
            </div>
            

            <Card sx={{width:'150vh', height:'40vh'}} >
                <CardContent>
                    <ScrollTable columns={nodeTableColumns} rowData={networkData.node_table} />
                </CardContent>
            </Card>
        </div>    
    </>
    )
}

export default Home;