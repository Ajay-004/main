const searchInput = document.getElementById('searchInput');
const resultsDiv = document.getElementById('results');

let diseases = [];

// Load the JSON data file
fetch('data.json')
  .then(response => response.json())
  .then(data => {
    diseases = data;
  })
  .catch(error => {
    resultsDiv.innerHTML = '<p>Error loading disease data.</p>';
    console.error('Error:', error);
  });

// Listen for input to filter and show matching diseases
searchInput.addEventListener('input', () => {
  const query = searchInput.value.trim().toLowerCase();
  if (query.length < 2) {
    resultsDiv.innerHTML = '';
    return;
  }

  const filtered = diseases.filter(disease => 
    disease.crop.toLowerCase().includes(query) ||
    disease.disease.toLowerCase().includes(query)
  );

  if (filtered.length === 0) {
    resultsDiv.innerHTML = '<p>No matching diseases found.</p>';
    return;
  }

  resultsDiv.innerHTML = filtered.map(disease => `
    <div class="disease-card">
      <img src="${disease.image}" alt="${disease.disease}" />
      <div class="disease-info">
        <h3>${disease.disease} (${disease.crop})</h3>
        <p><strong>Problem:</strong> ${disease.problem}</p>
        <p><strong>Cause:</strong> ${disease.cause}</p>
        <p><strong>Solution:</strong> ${disease.solution}</p>
        <p><strong>Prevention:</strong> ${disease.prevention}</p>
      </div>
    </div>
  `).join('');
});
