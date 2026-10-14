/** Generated client types. Run `npm run gen:api` when an OpenAPI file is exported. */
export interface paths {
  '/api/v1/login': {
    post: {
      requestBody: { content: { 'application/json': { email: string; password: string } } };
    };
  };
}
