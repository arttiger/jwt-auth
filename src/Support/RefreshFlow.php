<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Support;

trait RefreshFlow
{
    /**
     * The refresh flow flag.
     */
    protected bool $refreshFlow = false;

    /**
     * Set the refresh flow flag.
     */
    public function setRefreshFlow(bool $refreshFlow = true): self
    {
        $this->refreshFlow = $refreshFlow;

        return $this;
    }
}
