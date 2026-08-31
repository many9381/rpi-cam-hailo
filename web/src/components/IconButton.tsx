import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from 'react';

interface IconButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'children'> {
  label: string;
  children: ReactNode;
}

export const IconButton = forwardRef<HTMLButtonElement, IconButtonProps>(
  function IconButton({ label, className = '', type = 'button', children, ...props }, ref) {
    return (
      <button
        ref={ref}
        type={type}
        className={`icon-button ${className}`.trim()}
        aria-label={label}
        title={label}
        {...props}
      >
        {children}
      </button>
    );
  },
);
