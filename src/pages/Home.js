import { useLocation, useNavigate } from 'react-router-dom';
import NetworkGraph from '../comps/NetworkGraph';
import { Card, CardContent } from '@mui/material';
import ScrollTable from '../comps/ScrollTable';
import Hamburger from 'hamburger-react'
import { slide as Menu } from 'react-burger-menu'
import { useState } from 'react';

const Home = () => {

    const location = useLocation();
    const data = location.state;
    const [isOpen, setOpen] = useState(false)

    const nodeTableColumns = [
        { id: 'mac_addr', label: 'MAC ADDRESS (ID)', minWidth: 170 }, 
        { id: 'uplink_total', label: 'Uplink Total (MB)', minWidth: 200 },
        { id: 'downlink_total', label: 'Downlink Total (MB)', minWidth: 200 },   
    ]

    return (
    
    <>  
        {/* <Hamburger toggled={isOpen} toggle={setOpen} /> */}
        <>
        <Menu>
        <a id="home" className="menu-item" href="/">Home</a>
        </Menu>
        </>
        <div style={{ height: '100vh' }}>
            <div style={{alignItems: 'center'}}>
                <h1 > Home </h1>
            </div>
            
            <Card sx={{ width:'100vh', height:'75vh' }} >
                <CardContent>
                    <NetworkGraph data={data.network_graph} />
                </CardContent>
            </Card>

            <Card sx={{width:'150vh', height:'40vh'}} >
                <CardContent>
                    <ScrollTable columns={nodeTableColumns} rowData={data.node_table} />
                </CardContent>
            </Card>
        </div>    
    </>
    )


}

export default Home;