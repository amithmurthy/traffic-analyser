import { useLocation } from 'react-router-dom';
import NetworkGraph from '../comps/NetworkGraph';
import { Card, CardContent } from '@mui/material';

const Home = () => {

    const location = useLocation();
    const data = location.state;
    

    return (
    
    <>
        <div style={{ height: '100vh' }}>
            <div style={{alignItems: 'center'}}>
                <h1 > Home </h1>
            </div>
            
            <Card sx={{ width:'100vh', height:'75vh' }} >
                <CardContent>
                    <NetworkGraph data={data} />
                </CardContent>
            </Card>
        </div>    
    </>
    )


}

export default Home;