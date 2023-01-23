import ThroughputCard from "../comps/ThroughputChart"
import { useParams } from "react-router-dom"
import Sidebar from "../comps/Sidebar";

const NodeView = () => {
    let params = useParams();
    

    
//  // <ThroughputCard data = {data.throughput} />
    return (
        <>
            <Sidebar pageWrapId={'page-wrap'} outerContainerId={'outer-container'} />
            <h1 className="centered"> Node: {params.nodeId}</h1>
        </>
    )
}

export default NodeView;