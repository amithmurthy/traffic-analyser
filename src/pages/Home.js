import { useLocation, useNavigate } from 'react-router-dom';
import NetworkGraph from '../comps/NetworkGraph';
import Sidebar from '../comps/Sidebar';
import { Card, CardContent } from '@mui/material';
import ScrollTable from '../comps/ScrollTable';
import { useEffect, useState } from 'react';
import { DataGrid } from '@mui/x-data-grid';
import { ThemeProvider, createTheme } from '@material-ui/core';
import CssBaseline from '@mui/material/CssBaseline';

// style={{alignItems: 'center'}}
const Home = () => {

    const location = useLocation();
    const networkData = location.state;
    
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
    
    const columns = [
        {field: 'index', headerName:'Index', width:100},
        {field: 'mac_addr', headerName:'MAC Addr', width:100},
    ]

    const rows = [
        { id: 1, lastName: 'Snow', firstName: 'Jon', age: 35 },
        { id: 2, lastName: 'Lannister', firstName: 'Cersei', age: 42 },
        { id: 3, lastName: 'Lannister', firstName: 'Jaime', age: 45 },
        { id: 4, lastName: 'Stark', firstName: 'Arya', age: 16 },
        { id: 5, lastName: 'Targaryen', firstName: 'Daenerys', age: null },
        { id: 6, lastName: 'Melisandre', firstName: null, age: 150 },
        { id: 7, lastName: 'Clifford', firstName: 'Ferrara', age: 44 },
        { id: 8, lastName: 'Frances', firstName: 'Rossini', age: 36 },
        { id: 9, lastName: 'Roxie', firstName: 'Harvey', age: 65 },
    ];

    // const getIndex = (row) => {
    //     let i = rows.getIndex(r => r.ID === row.ID)
    //     return i
    // }

    // const columns = [
    //     {field: 'index', headerName:'index', renderCell: (params) => {getIndex(params.row)}},
    //     {
    //       field: 'firstName',
    //       headerName: 'First name',
    //       width: 150,
    //       editable: true,
    //     },
    //     {
    //       field: 'lastName',
    //       headerName: 'Last name',
    //       width: 150,
    //       editable: true,
    //     },
    //     {
    //       field: 'age',
    //       headerName: 'Age',
    //       type: 'number',
    //       width: 110,
    //       editable: true,
    //     },
    //     {
    //       field: 'fullName',
    //       headerName: 'Full name',
    //       description: 'This column has a value getter and is not sortable.',
    //       sortable: false,
    //       width: 160,
    //       valueGetter: (params) =>
    //         `${params.row.firstName || ''} ${params.row.lastName || ''}`,
    //     },
    //   ];
    
    const darkTheme = createTheme({
        palette: {
          mode: 'dark',
        },
    });
      



    const nodeTableColumns = [
        { id: 'mac_addr', label: 'MAC ADDRESS (ID)', minWidth: 170 }, 
        { id: 'uplink_total', label: 'Uplink Total (MB)', minWidth: 200 },
        { id: 'downlink_total', label: 'Downlink Total (MB)', minWidth: 200 },   
    ]

    return (
    <ThemeProvider theme={darkTheme}>
        <CssBaseline />
        <main >  
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

                {/* <Card sx={{width:'80vw', height:'60vh', marginLeft:'auto', marginRight:'auto', marginTop:'2vh'}} > */}
                    {/* <CardContent> */}
                        <ScrollTable columns={nodeTableColumns} rowData={networkData.node_table} sx={{}}/>
                        {/* <DataGrid columns={columns} rows={rows} get={row => row.ID} /> */}
                    {/* </CardContent> */}
                {/* </Card> */}
            </div>    
        </main>
    </ThemeProvider>

    )
}

export default Home;