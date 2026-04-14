import { createTheme } from '@mui/material/styles';

const adminTheme = createTheme({
  palette: {
    mode: 'light',
    background: {
      default: '#f4f6f9',
      paper: '#ffffff',
    },
    primary: {
      main: '#007bff',
    },
    secondary: {
      main: '#6c757d',
    },
    success: {
      main: '#28a745',
    },
    warning: {
      main: '#ffc107',
    },
    error: {
      main: '#dc3545',
    },
    text: {
      primary: '#212529',
      secondary: '#6c757d',
    },
    divider: '#dee2e6',
  },
  shape: {
    borderRadius: 4,
  },
  typography: {
    fontFamily: '"Inter", system-ui, -apple-system, sans-serif',
  },
  components: {
    MuiCssBaseline: {
      styleOverrides: {
        body: {
          backgroundColor: '#f4f6f9',
          color: '#212529',
        },
      },
    },
  },
});

export const theme = adminTheme;
export const darkTheme = adminTheme;
export const lightTheme = adminTheme;
export default adminTheme;
