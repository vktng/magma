// Code generated by go-swagger; DO NOT EDIT.

package network_probes

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"

	strfmt "github.com/go-openapi/strfmt"
)

// NewDeleteLTENetworkIDNetworkProbeDestinationsDestinationIDParams creates a new DeleteLTENetworkIDNetworkProbeDestinationsDestinationIDParams object
// with the default values initialized.
func NewDeleteLTENetworkIDNetworkProbeDestinationsDestinationIDParams() *DeleteLTENetworkIDNetworkProbeDestinationsDestinationIDParams {
	var ()
	return &DeleteLTENetworkIDNetworkProbeDestinationsDestinationIDParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewDeleteLTENetworkIDNetworkProbeDestinationsDestinationIDParamsWithTimeout creates a new DeleteLTENetworkIDNetworkProbeDestinationsDestinationIDParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewDeleteLTENetworkIDNetworkProbeDestinationsDestinationIDParamsWithTimeout(timeout time.Duration) *DeleteLTENetworkIDNetworkProbeDestinationsDestinationIDParams {
	var ()
	return &DeleteLTENetworkIDNetworkProbeDestinationsDestinationIDParams{

		timeout: timeout,
	}
}

// NewDeleteLTENetworkIDNetworkProbeDestinationsDestinationIDParamsWithContext creates a new DeleteLTENetworkIDNetworkProbeDestinationsDestinationIDParams object
// with the default values initialized, and the ability to set a context for a request
func NewDeleteLTENetworkIDNetworkProbeDestinationsDestinationIDParamsWithContext(ctx context.Context) *DeleteLTENetworkIDNetworkProbeDestinationsDestinationIDParams {
	var ()
	return &DeleteLTENetworkIDNetworkProbeDestinationsDestinationIDParams{

		Context: ctx,
	}
}

// NewDeleteLTENetworkIDNetworkProbeDestinationsDestinationIDParamsWithHTTPClient creates a new DeleteLTENetworkIDNetworkProbeDestinationsDestinationIDParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewDeleteLTENetworkIDNetworkProbeDestinationsDestinationIDParamsWithHTTPClient(client *http.Client) *DeleteLTENetworkIDNetworkProbeDestinationsDestinationIDParams {
	var ()
	return &DeleteLTENetworkIDNetworkProbeDestinationsDestinationIDParams{
		HTTPClient: client,
	}
}

/*DeleteLTENetworkIDNetworkProbeDestinationsDestinationIDParams contains all the parameters to send to the API endpoint
for the delete LTE network ID network probe destinations destination ID operation typically these are written to a http.Request
*/
type DeleteLTENetworkIDNetworkProbeDestinationsDestinationIDParams struct {

	/*DestinationID
	  Network Probe Destination ID

	*/
	DestinationID string
	/*NetworkID
	  Network ID

	*/
	NetworkID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the delete LTE network ID network probe destinations destination ID params
func (o *DeleteLTENetworkIDNetworkProbeDestinationsDestinationIDParams) WithTimeout(timeout time.Duration) *DeleteLTENetworkIDNetworkProbeDestinationsDestinationIDParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the delete LTE network ID network probe destinations destination ID params
func (o *DeleteLTENetworkIDNetworkProbeDestinationsDestinationIDParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the delete LTE network ID network probe destinations destination ID params
func (o *DeleteLTENetworkIDNetworkProbeDestinationsDestinationIDParams) WithContext(ctx context.Context) *DeleteLTENetworkIDNetworkProbeDestinationsDestinationIDParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the delete LTE network ID network probe destinations destination ID params
func (o *DeleteLTENetworkIDNetworkProbeDestinationsDestinationIDParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the delete LTE network ID network probe destinations destination ID params
func (o *DeleteLTENetworkIDNetworkProbeDestinationsDestinationIDParams) WithHTTPClient(client *http.Client) *DeleteLTENetworkIDNetworkProbeDestinationsDestinationIDParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the delete LTE network ID network probe destinations destination ID params
func (o *DeleteLTENetworkIDNetworkProbeDestinationsDestinationIDParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithDestinationID adds the destinationID to the delete LTE network ID network probe destinations destination ID params
func (o *DeleteLTENetworkIDNetworkProbeDestinationsDestinationIDParams) WithDestinationID(destinationID string) *DeleteLTENetworkIDNetworkProbeDestinationsDestinationIDParams {
	o.SetDestinationID(destinationID)
	return o
}

// SetDestinationID adds the destinationId to the delete LTE network ID network probe destinations destination ID params
func (o *DeleteLTENetworkIDNetworkProbeDestinationsDestinationIDParams) SetDestinationID(destinationID string) {
	o.DestinationID = destinationID
}

// WithNetworkID adds the networkID to the delete LTE network ID network probe destinations destination ID params
func (o *DeleteLTENetworkIDNetworkProbeDestinationsDestinationIDParams) WithNetworkID(networkID string) *DeleteLTENetworkIDNetworkProbeDestinationsDestinationIDParams {
	o.SetNetworkID(networkID)
	return o
}

// SetNetworkID adds the networkId to the delete LTE network ID network probe destinations destination ID params
func (o *DeleteLTENetworkIDNetworkProbeDestinationsDestinationIDParams) SetNetworkID(networkID string) {
	o.NetworkID = networkID
}

// WriteToRequest writes these params to a swagger request
func (o *DeleteLTENetworkIDNetworkProbeDestinationsDestinationIDParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param destination_id
	if err := r.SetPathParam("destination_id", o.DestinationID); err != nil {
		return err
	}

	// path param network_id
	if err := r.SetPathParam("network_id", o.NetworkID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}