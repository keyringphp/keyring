<?php

declare(strict_types=1);

namespace Keyring\Tests\Fixtures;

use Illuminate\Foundation\Http\FormRequest;

/**
 * A form request with nothing to check: a copy of request(), as a
 * controller of the app's own is given one.
 */
class PlainFormRequest extends FormRequest
{
    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [];
    }
}
