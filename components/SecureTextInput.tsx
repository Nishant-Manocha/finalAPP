import React, { forwardRef } from 'react';
import { TextInput, TextInputProps } from 'react-native';

export interface SecureTextInputProps extends TextInputProps {}

const SecureTextInput = forwardRef<TextInput, SecureTextInputProps>((props, ref) => {
  return (
    <TextInput
      ref={ref}
      // Security-hardening props; style comes from caller
      contextMenuHidden={true}
      selectTextOnFocus={false}
      autoCorrect={false}
      autoCapitalize="none"
      spellCheck={false}
      {...props}
    />
  );
});

SecureTextInput.displayName = 'SecureTextInput';

export default SecureTextInput;
