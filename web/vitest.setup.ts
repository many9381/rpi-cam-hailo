import '@testing-library/jest-dom/vitest';
import { configure } from '@testing-library/react';

// The suite also runs as the WebAppTest ctest case, in parallel with the C++
// tests on the device. Testing Library's 1 s default for findBy*/waitFor is
// too tight under that load (route transitions were seen at 1.6 s); the
// assertions are unchanged, only the tolerance grows.
configure({ asyncUtilTimeout: 5000 });
