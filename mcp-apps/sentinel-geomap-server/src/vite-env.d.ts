/// <reference types="vite/client" />

// Allow importing SVG files as raw strings
declare module '*.svg?raw' {
  const content: string;
  export default content;
}
