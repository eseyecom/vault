import Component from '@ember/component';
import { computed } from '@ember/object';
import autosize from 'autosize';

/**
 * @module MaskedInput
 * `MaskedInput` components are textarea inputs where the input is hidden. They are used to enter sensitive information like passwords.
 *
 * @example
 * ```js
 * <MaskedInput
 *  @value={{attr.options.defaultValue}}
 *  @placeholder="secret"
 *  @allowCopy={{true}}
 * />
 * ```
 *
 * @param [value] {String} - The value to display in the input.
 * @param [placeholder=value] {String} - The placeholder to display before the user has entered any input.
 * @param [allowCopy=null] {bool} - Whether or not the input should render with a copy button.
 * @param [displayOnly=false] {bool} - Whether or not to display the value as a display only `pre` element or as an input.
 *
 */

export default Component.extend({
  value: null,
  placeholder: 'value',
  didInsertElement() {
    this._super(...arguments);
    autosize(this.element.querySelector('textarea'));
  },
  didUpdate() {
    this._super(...arguments);
    autosize.update(this.element.querySelector('textarea'));
  },
  willDestroyElement() {
    this._super(...arguments);
    autosize.destroy(this.element.querySelector('textarea'));
  },
  shouldObscure: computed('isMasked', 'isFocused', 'value', function() {
    if (this.get('value') === '') {
      return false;
    }
    if (this.get('isFocused') === true) {
      return false;
    }
    return this.get('isMasked');
  }),
  displayValue: computed('shouldObscure', function() {
    if (this.get('shouldObscure')) {
      return '■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■ ■';
    } else {
      return this.get('value');
    }
  }),
  isMasked: true,
  isFocused: false,
  displayOnly: false,
  onKeyDown() {},
  onChange() {},
  actions: {
    toggleMask() {
      this.toggleProperty('isMasked');
    },
    updateValue(e) {
      this.set('value', e.target.value);
      this.onChange();
    },
  },
});
