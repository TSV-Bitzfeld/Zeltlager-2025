const { useState } = React;

// Error Boundary Component
class ErrorBoundary extends React.Component {
    constructor(props) {
        super(props);
        this.state = { hasError: false, error: null };
    }

    static getDerivedStateFromError(error) {
        return { hasError: true, error };
    }

    componentDidCatch(error, errorInfo) {
        console.error('React Error Boundary caught an error:', error, errorInfo);
    }

    render() {
        if (this.state.hasError) {
            return null; // Fall back to HTML version
        }
        return this.props.children;
    }
}

// Main Login Component
const AdminLogin = ({ flashMessages = [], csrfToken = '' }) => {
    const [password, setPassword] = useState('');

    return (
        React.createElement('div', { className: "min-h-screen bg-gray-50 flex items-center justify-center p-4" },
            React.createElement('div', { className: "w-full max-w-md bg-white rounded-lg shadow-md p-6" },
                React.createElement('div', { className: "text-center mb-6" },
                    React.createElement('h2', { className: "text-2xl font-bold" }, "Admin Login"),
                    React.createElement('p', { className: "text-gray-600" }, 
                        "Bitte melden Sie sich an, um fortzufahren"
                    )
                ),
                
                React.createElement('form', { method: "POST", className: "space-y-4" },
                    React.createElement('input', { 
                        type: "hidden", 
                        name: "csrf_token", 
                        value: csrfToken 
                    }),
                    
                    React.createElement('div', null,
                        React.createElement('label', { 
                            htmlFor: "password", 
                            className: "block text-sm font-medium text-gray-700 mb-1"
                        }, "Passwort"),
                        React.createElement('div', { className: "relative" },
                            React.createElement('input', {
                                type: "password",
                                id: "password",
                                name: "password",
                                value: password,
                                onChange: (e) => setPassword(e.target.value),
                                className: "block w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500",
                                required: true
                            })
                        )
                    ),

                    React.createElement('button', {
                        type: "submit",
                        className: "w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                    }, "Anmelden")
                ),

                flashMessages && flashMessages.length > 0 && 
                    React.createElement('div', { className: "mt-4 space-y-2" },
                        flashMessages.map((message, index) => 
                            React.createElement('div', { 
                                key: index,
                                className: message.category === 'success' 
                                    ? 'p-4 rounded-md bg-green-50 text-green-800'
                                    : 'p-4 rounded-md bg-red-50 text-red-800'
                            }, message.text)
                        )
                    )
            )
        )
    );
};

// Render with error boundary
document.addEventListener('DOMContentLoaded', () => {
    try {
        const rootElement = document.getElementById('root');
        const root = ReactDOM.createRoot(rootElement);
        
        // Pass flashMessages from the template if they exist
        const flashMessages = window.ADMIN_LOGIN_DATA?.flashMessages || [];
        const csrfToken = window.ADMIN_LOGIN_DATA?.csrfToken || '';

        root.render(
            React.createElement(ErrorBoundary, null,
                React.createElement(AdminLogin, { 
                    flashMessages: flashMessages,
                    csrfToken: csrfToken
                })
            )
        );
    } catch (error) {
        console.error('Error rendering React component:', error);
    }
});