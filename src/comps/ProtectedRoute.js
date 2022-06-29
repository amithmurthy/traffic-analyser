import { Navigate } from 'react-router-dom'


const ProtectedRoute = (isAllowed, redirect='/404') => {
    if (!isAllowed){
        return <Navigate to={redirect} replace/>
    }

}

export default ProtectedRoute;