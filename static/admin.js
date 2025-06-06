const DeleteConfirmModal = ({ isOpen, onConfirm, onCancel }) => {
   if (!isOpen) return null;
   
   return (
       <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
           <div className="bg-white p-6 rounded-lg shadow-lg w-96 mx-4">
               <h3 className="text-lg font-bold mb-4">Löschen bestätigen</h3>
               <p className="mb-6">Möchten Sie diesen Eintrag wirklich löschen?</p>
               <div className="flex justify-end space-x-3">
                   <button onClick={onCancel} className="px-4 py-2 bg-gray-200 rounded hover:bg-gray-300">
                       Abbrechen
                   </button>
                   <button onClick={onConfirm} className="px-4 py-2 bg-red-600 text-white rounded hover:bg-red-700">
                       Löschen
                   </button>
               </div>
           </div>
       </div>
   );
};

const formatDate = (dateString) => {
    if (!dateString) return '';
    
    // Erwartet YYYY-MM-DD Format aus der Datenbank
    const parts = dateString.split('-');
    if (parts.length === 3) {
        const [year, month, day] = parts;
        return `${day}.${month}.${year}`;
    }
    return dateString; // Fallback
};

const shortenCakeDonation = (cakeText) => {
    if (!cakeText) return '';
    if (cakeText.toLowerCase().includes('freitag')) return 'Freitag';
    if (cakeText.toLowerCase().includes('sonntag')) return 'Sonntag';
    return cakeText; // Fallback für unbekannte Texte
};

const shortenHelpOrganisation = (helpText) => {
    if (!helpText) return '';
    if (helpText.toLowerCase().includes('aufbau')) return 'Aufbau';
    if (helpText.toLowerCase().includes('abbau')) return 'Abbau';
    return helpText; // Fallback für unbekannte Texte
};

const AdminDashboard = () => {
   const [showDeleteConfirm, setShowDeleteConfirm] = React.useState(false);
   const { registrations, stats, csrfToken } = window.ADMIN_DATA;

   React.useEffect(() => {
       // Initial call to handle any flash messages present on load
       handleFlashMessages();

       // Set up a mutation observer to watch for new flash messages
       const observer = new MutationObserver((mutations) => {
           mutations.forEach((mutation) => {
               if (mutation.addedNodes.length) {
                   handleFlashMessages();
               }
           });
       });

       // Start observing the body for changes
       observer.observe(document.body, { childList: true, subtree: true });

       // Cleanup observer on component unmount
       return () => observer.disconnect();
   }, []);

   return (
       <div className="min-h-screen bg-gray-50 p-4 md:p-8">
           <div className="max-w-7xl mx-auto">
               {/* Header */}
               <div className="flex justify-between items-center mb-8">
                   <h1 className="text-3xl font-bold text-gray-900">Admin Dashboard</h1>
                   <div className="flex gap-4">
                       <a 
                           href="/export-excel"
                           className="inline-flex items-center px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700"
                       >
                           Excel Export
                       </a>
                       <a 
                           href="/logout"
                           className="inline-flex items-center px-4 py-2 bg-gray-600 text-white rounded-md hover:bg-gray-700"
                       >
                           Logout
                       </a>
                   </div>
               </div>

               {/* Stats Cards */}
               <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4 mb-8">
                   <div className="bg-white p-4 rounded-lg shadow">
                       <h3 className="text-sm font-semibold text-gray-600">Anzahl Anmeldungen</h3>
                       <p className="text-2xl font-bold mt-1 text-black">{stats.total_registrations}</p>
                   </div>
                   <div className="bg-white p-4 rounded-lg shadow">
                       <h3 className="text-sm font-semibold text-gray-600">Angemeldete Kinder</h3>
                       <p className="text-2xl font-bold mt-1 text-black">{stats.total_children}</p>
                   </div>
                   <div className="bg-white p-4 rounded-lg shadow">
                       <h3 className="text-sm font-semibold text-gray-600">Kuchen Freitag</h3>
                       <p className="text-2xl font-bold mt-1 text-black">{stats.cake_friday_count}</p>
                   </div>
                   <div className="bg-white p-4 rounded-lg shadow">
                       <h3 className="text-sm font-semibold text-gray-600">Kuchen Sonntag</h3>
                       <p className="text-2xl font-bold mt-1 text-black">{stats.cake_sunday_count}</p>
                   </div>
                   <div className="bg-white p-4 rounded-lg shadow">
                       <h3 className="text-sm font-semibold text-gray-600">Aufbau Donnerstag</h3>
                       <p className="text-2xl font-bold mt-1 text-black">{stats.help_thursday_count}</p>
                   </div>
                   <div className="bg-white p-4 rounded-lg shadow">
                       <h3 className="text-sm font-semibold text-gray-600">Abbau Sonntag</h3>
                       <p className="text-2xl font-bold mt-1 text-black">{stats.help_sunday_count}</p>
                   </div>
               </div>

               {/* Registrations Table */}
               <div className="bg-white rounded-lg shadow overflow-hidden">
                   <div className="overflow-x-auto">
                       <table className="w-full">
                           <thead className="bg-gray-50">
                               <tr>
                                   <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                       Zeitstempel
                                   </th>
                                   <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                       Kind/er
                                   </th>
                                   <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                       Erziehungsberechtigte/r
                                   </th>
                                   <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                       Aktionen
                                   </th>
                               </tr>
                           </thead>
                           <tbody className="bg-white divide-y divide-gray-200">
                               {registrations.map((registration) => {
                                   const [showModal, setShowModal] = React.useState(false);
                                   const formRef = React.useRef();
                                   
                                   return (
                                       <tr key={registration.id} className={registration.confirmed ? 'bg-green-50' : ''}>
                                           <td className="px-6 py-4 whitespace-nowrap">
                                               {registration.created_at}
                                           </td>
                                           <td className="px-6 py-4">
                                               {registration.persons.map((person, idx) => (
                                                   <div key={idx} className="mb-2">
                                                       <p className="font-medium">{person.person_firstname} {person.person_lastname}</p>
                                                       <p className="text-sm">Geb.: {formatDate(person.birthdate)}</p>
                                                       <p className="text-sm">Verein: {person.club_membership}</p>
                                                   </div>
                                               ))}
                                           </td>
                                           <td className="px-6 py-4">
                                                   <div className="mb-2">
                                                       <p className="font-medium">{registration.contact_firstname} {registration.contact_lastname}</p>
                                                       {registration.contact_birthdate && <p className="text-sm">Geb.: {formatDate(registration.contact_birthdate)}</p>}
                                                       <p className="text-sm">Telefonnummer: {registration.phone_number}</p>
                                                       <p className="text-sm">E-Mail: {registration.email}</p>
                                                       <p className="text-sm">Kuchenspende am {shortenCakeDonation(registration.cake_donation)}</p>
                                                       <p className="text-sm">Hilft beim {shortenHelpOrganisation(registration.help_organisation)}</p>
                                                   </div>
                                           </td>
                                           <td className="px-6 py-4">
                                               <div className="flex flex-col space-y-2">
                                                   <a 
                                                       href={`/edit-entry/${registration.id}`}
                                                       className="w-full px-4 py-2 text-white bg-blue-600 hover:bg-blue-700 rounded-md text-center block no-underline"
                                                   >
                                                       Bearbeiten
                                                   </a>
                                                   <form ref={formRef} action={`/delete-entry/${registration.id}`} method="post">
                                                       <input type="hidden" name="csrf_token" value={csrfToken} />
                                                       <button
                                                           type="button"
                                                           onClick={() => setShowModal(true)}
                                                           className="w-full px-4 py-2 text-white bg-red-600 hover:bg-red-700 rounded-md"
                                                       >
                                                           Löschen
                                                       </button>
                                                       <DeleteConfirmModal 
                                                           isOpen={showModal}
                                                           onConfirm={() => {
                                                               formRef.current.submit();
                                                               setShowModal(false);
                                                           }}
                                                           onCancel={() => setShowModal(false)}
                                                       />
                                                   </form>
                                               </div>
                                           </td>
                                       </tr>
                                   );
                               })}
                           </tbody>
                       </table>
                   </div>
               </div>

               {/* Delete All Section */}
               <div className="mt-8">
                   {showDeleteConfirm ? (
                       <div className="bg-red-50 border border-red-200 rounded-md p-4">
                           <p className="text-red-800 mb-4">
                               Möchten Sie wirklich alle Einträge löschen? Diese Aktion kann nicht rückgängig gemacht werden.
                           </p>
                           <div className="flex space-x-4">
                               <form action="/delete-all-entries" method="post">
                                   <input type="hidden" name="csrf_token" value={csrfToken} />
                                   <button
                                       type="submit"
                                       className="px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700"
                                   >
                                       Ja, alle löschen
                                   </button>
                               </form>
                               <button
                                   onClick={() => setShowDeleteConfirm(false)}
                                   className="px-4 py-2 bg-gray-600 text-white rounded-md hover:bg-gray-700"
                               >
                                   Abbrechen
                               </button>
                           </div>
                       </div>
                   ) : (
                       <button
                           onClick={() => setShowDeleteConfirm(true)}
                           className="px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700"
                       >
                           Alle Einträge löschen
                       </button>
                   )}
               </div>
           </div>
       </div>
   );
};

function handleFlashMessages() {
    document.querySelectorAll('.flash-message:not([data-handled])').forEach(message => {
        message.dataset.handled = 'true';
        
        // Style for centered, boxed messages
        message.style.position = 'fixed';
        message.style.top = '50%';
        message.style.left = '50%';
        message.style.transform = 'translate(-50%, -50%)';
        message.style.backgroundColor = 'rgba(0, 0, 0, 1)';
        message.style.color = 'white';
        message.style.padding = '15px 30px';
        message.style.borderRadius = '8px';
        message.style.zIndex = '1000';
        message.style.textAlign = 'center';
        
        // Fade out and remove after 3 seconds
        setTimeout(() => {
            message.style.transition = 'opacity 0.5s';
            message.style.opacity = '0';
            setTimeout(() => message.remove(), 500);
        }, 3000);
    });
}

const rootElement = document.getElementById('root');
const root = ReactDOM.createRoot(rootElement);
root.render(<AdminDashboard />);