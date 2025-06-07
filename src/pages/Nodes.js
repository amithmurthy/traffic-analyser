import Sidebar from '../comps/Sidebar';

const Nodes = () => {


    return (
        <div>
            <Sidebar pageWrapId={'page-wrap'} outerContainerId={'outer-container'} />
            <div style={{display:'flex', flexDirection:'column', alignItems:'center'}}>

                <h3> All Nodes Here </h3>
            </div>
        </div>
    )
}

export default Nodes