import IconButton from '@mui/material/IconButton';
import Box from '@mui/material/Box';
import { useTheme, ThemeProvider, createTheme } from '@mui/material/styles';
import Brightness4Icon from '@mui/icons-material/Brightness4';
import Brightness7Icon from '@mui/icons-material/Brightness7';
import { useContext, createContext, useMemo, useState } from 'react';


const ColorModeContext = createContext({toggleColorMode: () => {}});


const ThemeButton = () => {
    const theme = useTheme();
    const colorMode = useContext(ColorModeContext);


    return (
        <IconButton sx={{ ml: 1 }} onClick={colorMode.toggleColorMode} color="inherit">
        {theme.palette.mode === 'dark' ? <Brightness7Icon /> : <Brightness4Icon />}
      </IconButton>
    )
}


const ThemeLayout = ({ children }) => {
    const [mode, setMode] = useState('light');
    const colorMode = useMemo(
        () => ({
        toggleColorMode: () => {
            setMode((prevMode) => (prevMode === 'light' ? 'dark' : 'light'));
        },
        }),
        [],
    );

    const theme = useMemo(
        () =>
          createTheme({
            palette: {
              mode,
            },
          }),
        [mode],
    );

    return (
        <ColorModeContext.Provider value={colorMode}>
        <ThemeProvider theme={theme}>
        <ThemeButton />
           {children} 
        </ThemeProvider>
      </ColorModeContext.Provider>
    )
}


export default ThemeLayout