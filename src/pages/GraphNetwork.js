import Graph  from 'react-vis-network-graph';
import { useLocation } from 'react-router-dom';



const GraphNetwork = () => {
    const location = useLocation();
    const data = location.state;

    const options = {
        layout: {
          hierarchical: false
        },
        edges: {
          color: "#000000"
        },
        // nodes: {
        //   shape: 'box',
        //   font: {
        //       size: 14,
        //       color: '#3f3f3f',
        //       strokeWidth: 3, 
        //       strokeColor: 'white',
        //       face: 'akrobat'
        //   },
        //   borderWidth: 2,
        //   color: {
        //       background: '#d7d7f3',
        //       border: '#3030a9',
        //   }  
        // },
        height: "100%",
        width:"100%",
        autoResize: true
      }
    
    const events = {
    select: function(event) {
        var {nodes, edges} = event;
        var request = {'node': nodes}
        window.electron.facadeAPI.sendRequest(request);
        window.electron.handle('facade', (event,data) => function(event,data) {
            console.log(event);
            console.log('node click event test');
        })
    }
    };



    return (
        <>
          <div style={{ height: '100vh' }}>
            <Graph
              graph={data}
              options={options}
              events={events} 
            />
          </div>
        </>
    )


}

export default GraphNetwork;